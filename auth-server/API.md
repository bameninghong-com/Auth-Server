# Auth Server — API Reference

## Base URL

```
http://localhost:3000
```

Alle Auth-Endpunkte folgen dem Schema `/auth/:tenant/...` wobei `:tenant` der
`slug` des Tenants ist (z.B. `projekt-alpha`).

---

## Authentifizierung

Der Auth Server verwendet zwei Token-Typen:

| Token | Wo | Lebensdauer |
|---|---|---|
| **Access Token** | `Authorization: Bearer <token>` Header | 15 Min (konfigurierbar) |
| **Refresh Token** | `httpOnly` Cookie (`refreshToken`) | 30 Tage (konfigurierbar) |

Für Non-Browser Clients (z.B. Mobile Apps) kann der Refresh Token alternativ
im Request Body als `refreshToken` übergeben werden.

---

## Endpunkte

### Health Check

```
GET /health
```

Prüft ob der Server läuft.

**Response `200`**
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

---

### Registrierung

```
POST /auth/:tenant/register
```

Legt einen neuen User an. Wenn `require_email_verification` für den Tenant
aktiv ist, wird eine Bestätigungs-E-Mail verschickt.

**Rate Limit:** 20 Requests / 15 Minuten

**Request Body**
```json
{
  "email": "user@example.com",
  "password": "sicheresPasswort123"
}
```

| Feld | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `email` | string | ✓ | Gültige E-Mail-Adresse |
| `password` | string | ✓ | Mindestens 8 Zeichen |

**Response `201` — Registrierung erfolgreich**
```json
{
  "message": "Registration successful. Please verify your email.",
  "emailVerificationRequired": true
}
```

**Fehler**

| Code | HTTP | Beschreibung |
|---|---|---|
| `EMAIL_TAKEN` | 409 | E-Mail bereits registriert |
| `VALIDATION_ERROR` | 422 | Eingabe ungültig |
| `TENANT_NOT_FOUND` | 404 | Tenant existiert nicht |

---

### Login

```
POST /auth/:tenant/login
```

Meldet einen User an. Gibt einen Access Token zurück und setzt den Refresh
Token als `httpOnly` Cookie.

**Rate Limit:** 20 Requests / 15 Minuten

**Request Body**
```json
{
  "email": "user@example.com",
  "password": "sicheresPasswort123"
}
```

**Response `200`**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

Der `refreshToken` wird automatisch als `httpOnly` Cookie gesetzt:
```
Set-Cookie: refreshToken=<token>; Path=/auth/refresh; HttpOnly; SameSite=Strict
```

**Access Token Payload (decoded)**
```json
{
  "sub": "user-uuid",
  "tenant_id": "tenant-uuid",
  "email": "user@example.com",
  "roles": ["admin"],
  "session_id": "session-uuid",
  "type": "access",
  "iat": 1705312200,
  "exp": 1705313100
}
```

**Fehler**

| Code | HTTP | Beschreibung |
|---|---|---|
| `INVALID_CREDENTIALS` | 401 | E-Mail oder Passwort falsch |
| `ACCOUNT_LOCKED` | 423 | Account nach zu vielen Fehlversuchen gesperrt |
| `ACCOUNT_INACTIVE` | 403 | Account deaktiviert |
| `EMAIL_NOT_VERIFIED` | 403 | E-Mail noch nicht bestätigt |

---

### Access Token erneuern

```
POST /auth/:tenant/refresh
```

Tauscht einen gültigen Refresh Token gegen einen neuen Access Token + neuen
Refresh Token (Rotation). Der alte Refresh Token wird dabei ungültig.

**Refresh Token Quellen (in dieser Reihenfolge):**
1. `refreshToken` Cookie (automatisch bei Browser-Clients)
2. Request Body `{ "refreshToken": "..." }` (für Mobile/API Clients)

**Response `200`**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Der neue Refresh Token wird wieder als Cookie gesetzt.

**Fehler**

| Code | HTTP | Beschreibung |
|---|---|---|
| `NO_TOKEN` | 401 | Kein Refresh Token übermittelt |
| `INVALID_TOKEN` | 401 | Token ungültig oder nicht gefunden |
| `TOKEN_EXPIRED` | 401 | Refresh Token abgelaufen |
| `SESSION_REVOKED` | 401 | Session wurde beendet |
| `TOKEN_THEFT` | 401 | Sicherheitsverletzung — alle Sessions gesperrt |

> **Token Theft Detection:** Wenn ein bereits rotierter Refresh Token nochmal
> verwendet wird, erkennt der Server einen möglichen Token-Diebstahl und
> sperrt sofort alle Sessions des Users.

---

### Logout

```
POST /auth/:tenant/logout
```

Beendet die aktuelle Session. Mit `?all=true` werden alle Sessions des Users
auf allen Geräten beendet.

**Authentifizierung erforderlich:** `Authorization: Bearer <accessToken>`

**Query Parameter**

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `all` | boolean | `false` | `true` = alle Geräte abmelden |

**Beispiele**
```
POST /auth/projekt-alpha/logout           → aktuelle Session beenden
POST /auth/projekt-alpha/logout?all=true  → alle Geräte abmelden
```

**Response `200`**
```json
{
  "message": "Logged out successfully"
}
```

oder bei `?all=true`:
```json
{
  "message": "Logged out from all devices"
}
```

Der `refreshToken` Cookie wird automatisch gelöscht.

---

### E-Mail verifizieren

```
GET /auth/verify-email?token=<token>&tenant=<slug>
```

Bestätigt die E-Mail-Adresse eines Users. Der Token wird per E-Mail zugeschickt
und ist 24 Stunden gültig.

**Query Parameter**

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `token` | string | ✓ | Verification Token aus der E-Mail |
| `tenant` | string | ✓ | Tenant Slug |

**Response `200`**
```json
{
  "message": "Email verified successfully"
}
```

**Fehler**

| Code | HTTP | Beschreibung |
|---|---|---|
| `INVALID_TOKEN` | 401 | Token nicht gefunden |
| `TOKEN_USED` | 410 | Token bereits verwendet |
| `TOKEN_EXPIRED` | 401 | Token abgelaufen (24h) |

---

### Passwort vergessen

```
POST /auth/:tenant/forgot-password
```

Schickt eine Passwort-Reset E-Mail. Gibt immer `200` zurück — auch wenn die
E-Mail nicht existiert (verhindert User-Enumeration).

**Rate Limit:** 5 Requests / Stunde

**Request Body**
```json
{
  "email": "user@example.com"
}
```

**Response `200`**
```json
{
  "message": "If this email exists, a reset link has been sent."
}
```

---

### Passwort zurücksetzen

```
POST /auth/reset-password
```

Setzt das Passwort mit dem Token aus der Reset-E-Mail. Der Token ist 1 Stunde
gültig. Nach erfolgreichem Reset werden alle aktiven Sessions des Users
beendet.

**Rate Limit:** 5 Requests / Stunde

**Request Body**
```json
{
  "token": "abc123...",
  "newPassword": "neuesPasswort456"
}
```

| Feld | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `token` | string | ✓ | Token aus der Reset-E-Mail |
| `newPassword` | string | ✓ | Mindestens 8 Zeichen |

**Response `200`**
```json
{
  "message": "Password reset successfully. Please log in again."
}
```

**Fehler**

| Code | HTTP | Beschreibung |
|---|---|---|
| `INVALID_TOKEN` | 401 | Token nicht gefunden |
| `TOKEN_USED` | 410 | Token bereits verwendet |
| `TOKEN_EXPIRED` | 401 | Token abgelaufen (1h) |

---

### Aktive Sessions abrufen

```
GET /auth/:tenant/sessions
```

Gibt alle aktiven Sessions des eingeloggten Users zurück — nützlich für eine
"Angemeldete Geräte" Übersicht.

**Authentifizierung erforderlich:** `Authorization: Bearer <accessToken>`

**Response `200`**
```json
{
  "sessions": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "deviceName": "Chrome 124 on Windows",
      "deviceType": "desktop",
      "os": "Windows",
      "browser": "Chrome 124",
      "ipAddress": "192.168.1.1",
      "country": "DE",
      "city": "Berlin",
      "lastUsedAt": "2024-01-15T10:28:00.000Z",
      "createdAt": "2024-01-10T08:00:00.000Z",
      "isCurrent": true
    },
    {
      "id": "661f9511-f30c-52e5-b827-557766551111",
      "deviceName": "Safari on iOS",
      "deviceType": "mobile",
      "os": "iOS",
      "browser": "Safari",
      "ipAddress": "192.168.1.2",
      "country": "DE",
      "city": "Berlin",
      "lastUsedAt": "2024-01-14T18:45:00.000Z",
      "createdAt": "2024-01-14T18:30:00.000Z",
      "isCurrent": false
    }
  ]
}
```

> `isCurrent: true` markiert die Session aus der der Request kommt.

---

### Session beenden (einzelnes Gerät abmelden)

```
DELETE /auth/:tenant/sessions/:sessionId
```

Beendet eine bestimmte Session. Die eigene aktuelle Session kann nicht über
diesen Endpunkt beendet werden — dafür `POST /logout` verwenden.

**Authentifizierung erforderlich:** `Authorization: Bearer <accessToken>`

**URL Parameter**

| Parameter | Typ | Beschreibung |
|---|---|---|
| `sessionId` | UUID | ID der zu beendenden Session (aus `/sessions`) |

**Response `200`**
```json
{
  "message": "Session revoked"
}
```

**Fehler**

| Code | HTTP | Beschreibung |
|---|---|---|
| `CANNOT_REVOKE_CURRENT` | 400 | Eigene Session — `/logout` verwenden |
| `UNAUTHORIZED` | 401 | Nicht eingeloggt |

---

## Vollständiges Flow-Beispiel

```bash
# 1. Registrieren
curl -X POST http://localhost:3000/auth/projekt-alpha/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"meinPasswort123"}'

# 2. E-Mail verifizieren (Token aus der Mail)
curl "http://localhost:3000/auth/verify-email?token=abc123&tenant=projekt-alpha"

# 3. Einloggen
curl -X POST http://localhost:3000/auth/projekt-alpha/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email":"user@example.com","password":"meinPasswort123"}'
# → gibt accessToken zurück, setzt refreshToken Cookie

# 4. Geschützten Endpunkt aufrufen (eigenes Projekt)
curl http://localhost:4000/api/profile \
  -H "Authorization: Bearer <accessToken>"

# 5. Access Token erneuern
curl -X POST http://localhost:3000/auth/projekt-alpha/refresh \
  -b cookies.txt
# → gibt neuen accessToken zurück

# 6. Alle aktiven Sessions anzeigen
curl http://localhost:3000/auth/projekt-alpha/sessions \
  -H "Authorization: Bearer <accessToken>"

# 7. Bestimmtes Gerät abmelden
curl -X DELETE http://localhost:3000/auth/projekt-alpha/sessions/<sessionId> \
  -H "Authorization: Bearer <accessToken>"

# 8. Ausloggen (alle Geräte)
curl -X POST "http://localhost:3000/auth/projekt-alpha/logout?all=true" \
  -H "Authorization: Bearer <accessToken>" \
  -b cookies.txt
```

---

## Fehlerformat

Alle Fehler folgen diesem einheitlichen Format:

```json
{
  "error": "FEHLER_CODE",
  "message": "Menschenlesbare Fehlerbeschreibung"
}
```

Bei Validierungsfehlern zusätzlich:
```json
{
  "error": "VALIDATION_ERROR",
  "message": "Validation failed",
  "issues": [
    {
      "path": ["email"],
      "message": "Invalid email"
    }
  ]
}
```

---

## JWT in eigenen Projekten verifizieren

```typescript
import jwt from 'jsonwebtoken'

const payload = jwt.verify(accessToken, process.env.JWT_SECRET) as {
  sub:        string   // user_id
  tenant_id:  string
  email:      string
  roles:      string[]
  session_id: string
}

// user_id als Anker zur eigenen Datenbank verwenden
const profile = await db.profiles.findOne({ userId: payload.sub })
```

> Der `JWT_SECRET` muss in allen Projekten identisch sein — einfach dieselbe
> `.env` Variable verwenden oder sicher teilen.
