# SSO v0.6 — Security Hardening

Production-oriented SSO/IdP prototype written in Go.

## Stack

- Go 1.25.0
- Docker build image: `golang:1.25-alpine`
- PostgreSQL
- Redis-ready architecture
- Bootstrap admin
- Local authentication
- LDAP / Active Directory Search + Bind
- OAuth2 Authorization Code Flow
- OpenID Connect Discovery, JWKS, ID Token and UserInfo
- RBAC for administrative APIs

## Start

```bash
docker compose build
docker compose up
```

Run migrations manually with your preferred migration tool. Migration files are in `migrations/`.

## Configuration

Release 0.5.1 standardizes all application environment variables under the `SSO_` namespace.

| Variable | Required | Example | Description |
| --- | --- | --- | --- |
| `SSO_ENV` | No | `local` | Runtime environment name. |
| `SSO_HTTP_ADDR` | No | `:8080` | HTTP listen address. |
| `SSO_DATABASE_URL` | Yes | `postgres://sso:sso@postgres:5432/sso?sslmode=disable` | PostgreSQL connection string. Use `postgres` as host inside Docker Compose. |
| `SSO_JWT_SECRET` | Yes | `change-me-please-change-me-please-change-me` | JWT signing secret. Must be at least 32 characters. |
| `SSO_ENCRYPTION_KEY` | Yes | `change-me-please-change-me-please-change-me` | Key for encrypting stored secrets (LDAP bind passwords) with AES-256-GCM. Must be at least 32 characters. |
| `SSO_ACCESS_TOKEN_TTL` | No | `15m` | Access token lifetime. |
| `SSO_SESSION_TTL` | No | `720h` | Session lifetime. |
| `SSO_REFRESH_TOKEN_TTL` | No | `720h` | OAuth2 refresh token lifetime. |
| `SSO_CORS_ALLOWED_ORIGINS` | No | `http://localhost:3000,http://localhost:5173,http://localhost:8080` | Comma-separated CORS allowed origins. |
| `SSO_ISSUER` | No | `http://localhost:8080` | OAuth2/OIDC issuer URL. |
| `SSO_OIDC_KEY_ROTATION_ENABLED` | No | `false` | Enables background OIDC signing key rotation (new key every 30 days; the previous key stays in JWKS for 24h). |
| `SSO_LOG_LEVEL` | No | `info` | JSON logger level: `debug`, `info`, `warn`, `error`. |

Deprecated variable names such as `DATABASE_URL`, `SSO_DB_URL`, `JWT_SECRET`, `ACCESS_TOKEN_TTL`, and `SESSION_TTL` are intentionally not supported by v0.5.1.

## Bootstrap

```http
GET /api/v1/bootstrap/status
POST /api/v1/bootstrap
```

Payload:

```json
{
  "username": "admin",
  "email": "admin@example.com",
  "password": "StrongPassword123"
}
```

## Auth

```http
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

## OAuth2 / OIDC

Discovery:

```http
GET /.well-known/openid-configuration
GET /.well-known/jwks.json
GET /oauth2/userinfo
```

Authorization Code Flow:

```http
GET /oauth2/authorize?response_type=code&client_id=app&redirect_uri=http://localhost/callback&scope=openid profile email&state=xyz&nonce=abc&code_challenge=...&code_challenge_method=S256
POST /oauth2/token
```

Refresh, revocation and introspection (v0.6):

```http
POST /oauth2/token       (grant_type=refresh_token&refresh_token=...)
POST /oauth2/revoke      (token=...)
POST /oauth2/introspect  (token=...)
```

The token endpoint returns a `refresh_token` alongside the access token. Refresh tokens are single-use and rotated on every refresh; reusing an already-rotated token revokes the entire token family. Client credentials are accepted as `client_secret_post` or `client_secret_basic`.

## Release 0.5 - RBAC

Release 0.5 adds role-based access control.

### New concepts

- Role: named collection of permissions.
- Permission: resource/action pair such as `users:create`.
- User role assignment: users receive permissions through roles.

### Default roles

Migration `000005_rbac` creates:

- `admin` - full access to all current permissions.
- `user` - regular user role.

For compatibility with previous releases, if the database already contains users and no role assignments exist, the migration grants `admin` to the earliest created user.

### New API

Protected by Bearer token and RBAC middleware:

```http
GET    /api/v1/roles
POST   /api/v1/roles
GET    /api/v1/permissions
GET    /api/v1/roles/{roleID}/permissions
POST   /api/v1/roles/{roleID}/permissions
DELETE /api/v1/roles/{roleID}/permissions/{permissionID}
GET    /api/v1/users/{userID}/roles
POST   /api/v1/users/{userID}/roles
DELETE /api/v1/users/{userID}/roles/{roleID}
```

### Bootstrap behavior

`POST /api/v1/bootstrap` now assigns the `admin` role to the first created administrator when RBAC migrations have been applied.

### Protected resources

The following admin APIs now require permissions:

- `users:*`
- `roles:*`
- `permissions:*`
- `ldap:*`
- `oauth_clients:*`

Run migrations before testing v0.5.1.

## Release 0.5.2 - Security Fixes

- The token endpoint now verifies the confidential client secret (Argon2id). Both `client_secret_post` and `client_secret_basic` are supported; invalid credentials return `401 invalid_client`.
- Requested scopes are validated against the client's `allowed_scopes`; unknown scopes are rejected with `invalid_scope`.
- LDAP bind passwords are encrypted at rest with AES-256-GCM using `SSO_ENCRYPTION_KEY` (new required variable). Rows written before 0.5.2 keep working and are re-encrypted on the next update.
- `SSO_OIDC_KEY_ROTATION_ENABLED=true` activates background signing key rotation.
- Invalid duration/boolean configuration values now fail startup with a clear error instead of panicking.

## Release 0.6 - Security Hardening

Run migration `000006_security_hardening` before starting v0.6.

- **Refresh tokens with rotation**: `grant_type=refresh_token` at `POST /oauth2/token`. Tokens are stored hashed, rotated on each use; reuse of a rotated token revokes the whole family (`refresh_token_reuse_detected` audit event). Lifetime is controlled by `SSO_REFRESH_TOKEN_TTL`.
- **Token revocation** (`POST /oauth2/revoke`, RFC 7009) and **introspection** (`POST /oauth2/introspect`, RFC 7662), both requiring client authentication and advertised in the discovery document.
- **Brute-force protection**: failed logins are counted per (username, IP); after 5 failures the pair is locked with exponential backoff (1m → 15m cap), `429` is returned and a `login_locked` audit event is written. Counters decay after 1 hour and reset on successful login.
- **Rate limiting**: in-memory token bucket (30 req/min, burst 10 per IP) on `/api/v1/auth/login`, `/oauth2/token` and `/api/v1/bootstrap`.
- **Audit log API**: `GET /api/v1/audit?actor=&action=&from=&to=&limit=&offset=` (RFC3339 timestamps), protected by the new `audit:read` permission.
- **Completed admin CRUD** (all RBAC-protected, with audit events):
  - `DELETE /api/v1/users/{id}` — soft delete (`users:delete`)
  - `PUT/DELETE /api/v1/roles/{roleID}` (`roles:update` / `roles:delete`); built-in `admin`/`user` roles cannot be deleted
  - `PUT/DELETE /api/v1/oauth/clients/{id}` (`oauth_clients:update` / `oauth_clients:delete`)
  - `PUT/DELETE /api/v1/ldap/providers/{id}` (`ldap:update` / `ldap:delete`); an empty `bind_password` on update keeps the stored secret
