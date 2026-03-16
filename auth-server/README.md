# Auth Server — Infrastructure Setup

## Projektstruktur

```
auth-server/
├── docker-compose.yml
├── .env.example
├── .env                    ← aus .env.example erstellen (nie in Git!)
├── .gitignore
├── test.sh                 ← Infrastruktur-Tests
│
└── init/
    └── sql/
        ├── 01_schema.sql   ← Datenbankschema
        └── 02_seed.sql     ← Erster Tenant + Admin-User (optional)
```

---

## Voraussetzungen

- Docker & Docker Compose installiert
- `openssl` verfügbar (macOS/Linux built-in, Windows: Git Bash)

---

## Erster Start

### Schritt 1 — .env erstellen

```bash
cp .env.example .env
```

Zwei Werte in `.env` befüllen:

```bash
# Datenbankpasswort generieren:
openssl rand -base64 32

# JWT Secret generieren (mind. 64 Zeichen):
openssl rand -base64 64
```

`.env` danach so aussehen:

```env
POSTGRES_PASSWORD=<generiertes-passwort>
JWT_SECRET=<generiertes-secret>
```

### Schritt 2 — Datenbank starten

```bash
docker compose up postgres -d
```

Warten bis der Container `healthy` ist:

```bash
docker compose ps
# STATUS sollte "healthy" zeigen
```

### Schritt 3 — Infrastruktur testen

```bash
chmod +x test.sh
./test.sh
```

Alle Tests grün → bereit für den Auth Server.

### Schritt 4 — Fertig

```bash
# Normaler Start:
docker compose up -d

# Mit pgAdmin (http://localhost:5050):
docker compose --profile dev up -d
```

---

## Nach einem Neustart

PostgreSQL startet automatisch mit allen Daten — kein weiterer Eingriff nötig.

```bash
docker compose up -d
```

---

## Neuen Tenant anlegen

Nur ein Datenbankeintrag — kein Secret nötig, da global über `JWT_SECRET`.

```bash
docker exec -e PGPASSWORD=$POSTGRES_PASSWORD auth_postgres \
  psql -U auth_user -d auth_db -c "
    INSERT INTO tenants (name, slug)
    VALUES ('Mein Projekt', 'mein-projekt');
  "
```

---

## JWT Secret rotieren

Das Secret in `.env` austauschen und den Auth Server neu starten.

> Alle bestehenden Tokens werden damit ungültig — alle User werden ausgeloggt.

```bash
# Neues Secret generieren:
openssl rand -base64 64

# In .env ersetzen, dann:
docker compose restart   # oder: Auth Server Prozess neu starten
```

---

## Abgelaufene Sessions aufräumen

Als Cron-Job alle 15 Minuten empfohlen:

```bash
# Einmalig manuell:
docker exec auth_postgres psql -U auth_user -d auth_db \
  -c "SELECT expire_sessions();"

# Als Cron (crontab -e):
*/15 * * * * docker exec auth_postgres psql -U auth_user -d auth_db -c "SELECT expire_sessions();" > /dev/null 2>&1
```

---

## Troubleshooting

**PostgreSQL startet nicht**
```bash
docker compose logs postgres
# Häufigste Ursache: POSTGRES_PASSWORD in .env nicht gesetzt
```

**Schema wurde nicht eingespielt**
Das Schema läuft nur beim allerersten Start (leeres Volume).
Bei Änderungen danach: Migration manuell ausführen oder Volume neu erstellen:
```bash
docker compose down -v   # ⚠ löscht alle Daten
docker compose up postgres -d
```

**Verbindung zu PostgreSQL testen**
```bash
docker exec -e PGPASSWORD=$POSTGRES_PASSWORD auth_postgres \
  psql -U auth_user -d auth_db -c "SELECT version();"
```

---

## Sicherheitshinweise

| Was | Regel |
|---|---|
| `.env` | Niemals in Git — enthält Passwort + JWT Secret |
| `JWT_SECRET` | Min. 64 Zeichen, zufällig generiert |
| `JWT_SECRET` Rotation | Loggt alle User aus — geplant durchführen |
| Port 5432 (PostgreSQL) | Nur auf `127.0.0.1` — nie direkt öffentlich erreichbar |
