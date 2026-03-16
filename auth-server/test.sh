#!/bin/bash
# ==============================================================================
# AUTH SERVER INFRASTRUCTURE — TEST SCRIPT
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

pass()    { echo -e "  ${GREEN}✓${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail()    { echo -e "  ${RED}✗${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
skip()    { echo -e "  ${YELLOW}~${NC} $1 ${YELLOW}(skipped)${NC}"; TESTS_SKIPPED=$((TESTS_SKIPPED + 1)); }
info()    { echo -e "  ${BLUE}i${NC} $1"; }
section() { echo -e "\n${BOLD}$1${NC}"; echo "────────────────────────────────────────"; }

# ── Load .env ─────────────────────────────────────────────────────────────────
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | grep -v '^$' | xargs)
  info "Loaded .env"
else
  echo -e "${RED}ERROR: .env not found. Run: cp .env.example .env${NC}"
  exit 1
fi

POSTGRES_USER="${POSTGRES_USER:-auth_user}"
POSTGRES_DB="${POSTGRES_DB:-auth_db}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   Auth Server Infrastructure Tests       ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"


# ==============================================================================
# 1. ENVIRONMENT
# ==============================================================================
section "1. Environment"

if [ -n "${POSTGRES_PASSWORD:-}" ]; then
  pass "POSTGRES_PASSWORD is set"
else
  fail "POSTGRES_PASSWORD is not set in .env"
fi

if [ -n "${JWT_SECRET:-}" ]; then
  JWT_LEN=${#JWT_SECRET}
  if [ "$JWT_LEN" -ge 64 ]; then
    pass "JWT_SECRET is set and long enough ($JWT_LEN chars)"
  else
    fail "JWT_SECRET is too short ($JWT_LEN chars) — minimum 64 characters"
  fi
else
  fail "JWT_SECRET is not set in .env"
fi


# ==============================================================================
# 2. DOCKER
# ==============================================================================
section "2. Docker"

if command -v docker &> /dev/null; then
  pass "Docker installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
else
  fail "Docker not found"
  exit 1
fi

if docker compose version &> /dev/null; then
  pass "Docker Compose available"
else
  fail "Docker Compose not found"
  exit 1
fi

STATUS=$(docker inspect --format='{{.State.Status}}' "auth_postgres" 2>/dev/null || echo "not_found")
if [ "$STATUS" = "running" ]; then
  pass "Container auth_postgres is running"
elif [ "$STATUS" = "not_found" ]; then
  fail "Container auth_postgres not found — run: docker compose up postgres -d"
else
  fail "Container auth_postgres status: $STATUS"
fi


# ==============================================================================
# 3. POSTGRESQL
# ==============================================================================
section "3. PostgreSQL"

if docker exec auth_postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q 2>/dev/null; then
  pass "PostgreSQL accepting connections"
else
  fail "PostgreSQL not ready"
fi

pg_query() {
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" auth_postgres \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAq -c "$1" 2>/dev/null
}

# Extensions
for ext in pgcrypto citext; do
  RESULT=$(pg_query "SELECT extname FROM pg_extension WHERE extname='$ext';" 2>/dev/null || echo "")
  if [ "$RESULT" = "$ext" ]; then
    pass "Extension '$ext' installed"
  else
    fail "Extension '$ext' missing"
  fi
done

# Tables
EXPECTED_TABLES="tenants users roles user_roles sessions session_events security_audit_log token_rotation_history email_verification_tokens password_reset_tokens"
for table in $EXPECTED_TABLES; do
  RESULT=$(pg_query "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename='$table';" 2>/dev/null || echo "")
  if [ "$RESULT" = "$table" ]; then
    pass "Table '$table' exists"
  else
    fail "Table '$table' missing"
  fi
done

# Ensure no vault_secret_ref column exists
HAS_VAULT_REF=$(pg_query "SELECT column_name FROM information_schema.columns WHERE table_name='tenants' AND column_name='vault_secret_ref';" 2>/dev/null || echo "")
if [ -z "$HAS_VAULT_REF" ]; then
  pass "No vault_secret_ref column (correct — JWT_SECRET is in .env)"
else
  fail "vault_secret_ref column still exists — schema not updated"
fi

# Views
for view in v_active_sessions v_user_security_overview; do
  RESULT=$(pg_query "SELECT viewname FROM pg_views WHERE schemaname='public' AND viewname='$view';" 2>/dev/null || echo "")
  if [ "$RESULT" = "$view" ]; then
    pass "View '$view' exists"
  else
    fail "View '$view' missing"
  fi
done

# Functions
for fn in set_updated_at expire_sessions revoke_all_user_sessions; do
  RESULT=$(pg_query "SELECT proname FROM pg_proc WHERE proname='$fn';" 2>/dev/null || echo "")
  if [ "$RESULT" = "$fn" ]; then
    pass "Function '$fn' exists"
  else
    fail "Function '$fn' missing"
  fi
done

# Triggers
for trigger in trg_tenants_updated_at trg_users_updated_at; do
  RESULT=$(pg_query "SELECT trigger_name FROM information_schema.triggers WHERE trigger_name='$trigger';" 2>/dev/null || echo "")
  if [ "$RESULT" = "$trigger" ]; then
    pass "Trigger '$trigger' exists"
  else
    fail "Trigger '$trigger' missing"
  fi
done

# Functional test: INSERT → UPDATE (trigger) → DELETE
TEST_SLUG="test-infra-$(date +%s)"
INSERT_ID=$(pg_query "
  INSERT INTO tenants (name, slug)
  VALUES ('Test Tenant', '$TEST_SLUG')
  RETURNING id;
" 2>/dev/null || echo "")

if [ -n "$INSERT_ID" ]; then
  pass "INSERT into tenants works"

  sleep 1
  TRIGGER_OK=$(pg_query "
    UPDATE tenants SET name='Updated' WHERE id='$INSERT_ID'
    RETURNING (updated_at > created_at);
  " 2>/dev/null || echo "")
  if [ "$TRIGGER_OK" = "t" ]; then
    pass "updated_at trigger fires correctly"
  else
    fail "updated_at trigger not working"
  fi

  pg_query "DELETE FROM tenants WHERE id='$INSERT_ID';" > /dev/null 2>&1
  pass "DELETE from tenants works"
else
  fail "INSERT into tenants failed"
fi

# expire_sessions function test
EXPIRE_RESULT=$(pg_query "SELECT expire_sessions();" 2>/dev/null || echo "error")
if [ "$EXPIRE_RESULT" != "error" ]; then
  pass "expire_sessions() executes successfully"
else
  fail "expire_sessions() failed"
fi


# ==============================================================================
# 4. NETWORK & SECURITY
# ==============================================================================
section "4. Network & Security"

# PostgreSQL not on 0.0.0.0
if command -v nc &> /dev/null; then
  if nc -z 0.0.0.0 5432 2>/dev/null; then
    fail "PostgreSQL port 5432 accessible on 0.0.0.0 — should be 127.0.0.1 only"
  else
    pass "PostgreSQL port 5432 not exposed on 0.0.0.0"
  fi
else
  skip "nc not available — skipping port exposure check"
fi

# Git checks
if [ -d ".git" ]; then
  if git ls-files --error-unmatch .env &>/dev/null 2>&1; then
    fail ".env is tracked by Git — add to .gitignore immediately"
  else
    pass ".env is not tracked by Git"
  fi
else
  skip "Not a Git repo — skipping Git checks"
fi

if [ -f ".gitignore" ]; then
  for entry in ".env"; do
    if grep -q "$entry" .gitignore 2>/dev/null; then
      pass ".gitignore includes '$entry'"
    else
      fail ".gitignore missing '$entry'"
    fi
  done
else
  fail ".gitignore not found"
fi


# ==============================================================================
# SUMMARY
# ==============================================================================
TOTAL=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   Results                                ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo -e "  Total:   $TOTAL tests"
echo -e "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed:  $TESTS_FAILED${NC}"
echo -e "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  ✓ All tests passed — infrastructure is ready!${NC}"
  echo ""
  exit 0
else
  echo -e "${RED}${BOLD}  ✗ $TESTS_FAILED test(s) failed — fix the issues above before continuing.${NC}"
  echo ""
  exit 1
fi
