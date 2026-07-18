# SSO v1.0 — Production Readiness

Single-tenant by design: this SSO serves exactly one company. Multi-tenancy (realms) is intentionally out of scope.

## Deployment

The binary serves plain HTTP and must run behind a TLS-terminating reverse proxy (nginx, traefik, Caddy) in production:

- Terminate HTTPS at the proxy and forward to `:8080`. The `sso_session` cookie sets `Secure` only when the request arrived over TLS, so terminate TLS at the proxy and forward the original scheme, or run the proxy on the same host.
- Set `SSO_TRUSTED_PROXIES` to the proxy's IP/CIDR. Only then is `X-Forwarded-For` honored for the client IP; from any other peer the header is ignored so a client cannot spoof its IP to evade per-IP brute-force lockout and rate limiting. Empty (default) = trust nobody, use the direct peer address.
- Provide real `SSO_JWT_SECRET` and `SSO_ENCRYPTION_KEY` (each ≥32 chars, e.g. `openssl rand -base64 48`) via a `.env` file or the orchestrator's secret store — never the committed defaults.
- `docker compose up` applies migrations automatically (`SSO_MIGRATE_ON_START=true`). For staged prod deploys keep it `false` and run migrations as a separate step.

Operational endpoints: `GET /health/live`, `GET /health/ready` (checks the DB), `GET /health/version`, `GET /metrics` (Prometheus text format).

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
| `SSO_MIGRATE_ON_START` | No | `false` | Apply embedded DB migrations on startup. |
| `SSO_TRUSTED_PROXIES` | No | — | Comma-separated CIDRs/IPs of reverse proxies allowed to set `X-Forwarded-For`. Empty = trust none. |
| `SSO_JWT_SECRET` | Yes | `change-me-please-change-me-please-change-me` | JWT signing secret. Must be at least 32 characters. |
| `SSO_ENCRYPTION_KEY` | Yes | `change-me-please-change-me-please-change-me` | Key for encrypting stored secrets (LDAP bind passwords) with AES-256-GCM. Must be at least 32 characters. |
| `SSO_ACCESS_TOKEN_TTL` | No | `15m` | Access token lifetime. |
| `SSO_SESSION_TTL` | No | `720h` | Session lifetime. |
| `SSO_REFRESH_TOKEN_TTL` | No | `720h` | OAuth2 refresh token lifetime. |
| `SSO_CORS_ALLOWED_ORIGINS` | No | `http://localhost:3000,http://localhost:5173,http://localhost:8080` | Comma-separated CORS allowed origins. |
| `SSO_ISSUER` | No | `http://localhost:8080` | OAuth2/OIDC issuer URL. |
| `SSO_OIDC_KEY_ROTATION_ENABLED` | No | `false` | Enables background OIDC signing key rotation (new key every 30 days; the previous key stays in JWKS for 24h). |
| `SSO_LOG_LEVEL` | No | `info` | JSON logger level: `debug`, `info`, `warn`, `error`. |
| `SSO_SMTP_HOST` | No | `smtp.example.org` | SMTP server. When empty, reset/verification mails are written to the application log (dev mode). |
| `SSO_SMTP_PORT` | No | `587` | SMTP port. |
| `SSO_SMTP_USERNAME` / `SSO_SMTP_PASSWORD` | No | — | SMTP credentials (plain auth). |
| `SSO_SMTP_FROM` | No | `sso@example.org` | Sender address; required to enable SMTP. |
| `SSO_SMTP_STARTTLS` | No | `true` | Upgrade the SMTP connection with STARTTLS. |

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

Logout, consent and service accounts (v0.6.5):

```http
GET/POST /oauth2/logout  (id_token_hint=...&post_logout_redirect_uri=...&state=...)
GET  /oauth2/consent?client_id=...&scope=...
POST /oauth2/consent     ({"client_id": "...", "scope": "..."})
POST /oauth2/token       (grant_type=client_credentials&scope=...)
```

All `/oauth2/*` errors follow RFC 6749: `{"error": "...", "error_description": "..."}`.

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

## Release 0.6.5 - OIDC Completeness

Run migration `000007_oidc_completeness` before starting v0.6.5.

- **RP-initiated logout**: `GET/POST /oauth2/logout` (advertised as `end_session_endpoint`). Accepts `id_token_hint` (validated against JWKS), `post_logout_redirect_uri` (must be registered in the client's `post_logout_redirect_uris`) and `state`. Revokes the SSO session and all refresh tokens of the user.
- **Back-channel logout**: if the client has `backchannel_logout_uri`, a signed `logout_token` (RS256) is POSTed to it on logout.
- **Consent**: `/oauth2/authorize` returns `403 consent_required` until the user grants the requested scopes. `GET /oauth2/consent` shows what is requested, `POST /oauth2/consent` grants it (scopes are merged with previous grants). Trusted first-party clients can set `skip_consent: true`.
- **client_credentials grant**: service-to-service tokens for confidential clients; `sub` is the client's internal id, no refresh or ID token, scope validated against `allowed_scopes`.
- **UserInfo scope filtering**: `profile` → `preferred_username`, `source`; `email` → `email`. Tokens without a scope claim keep the full response.
- New client fields: `post_logout_redirect_uris`, `backchannel_logout_uri`, `skip_consent` (create and update APIs). `GET /api/v1/oauth/clients/{id}` added.

## Release 0.7 - Admin UI

Vue 3 + Vite + Bootstrap 5 + Pinia + Vue Router + Axios (JavaScript) SPA in `web/admin/`.

Pages: sign-in, dashboard, users (CRUD + role assignment), roles (CRUD + permission assignment), OAuth clients (CRUD, one-time secret display), LDAP providers (CRUD + connection test), audit log (filters), and the OAuth consent screen (`/consent?client_id=...&scope=...&continue=<authorize URL>`).

- **Production**: `docker compose build` compiles the UI in a Node stage and the Go binary serves it from `web/admin/dist` on the same port (8080). Any unknown GET path falls back to `index.html` (SPA routing). If `web/admin/dist` is absent, the server runs API-only.
- **Development**: run the API locally, then `cd web/admin && npm install && npm run dev` — Vite serves the UI on :5173 and proxies `/api`, `/oauth2`, `/.well-known` and `/health` to :8080 (cookies flow same-origin, no CORS needed).
- Auth: the UI logs in via `POST /api/v1/auth/login`, stores the Bearer token and relies on the `sso_session` cookie for the OAuth authorize/consent/logout flows. On 401 it redirects to `/login?continue=...`.

## Release 0.8 - Accounts & MFA

Run migration `000008_accounts_mfa` before starting v0.8.

**Password reset & email verification**
- `POST /api/v1/auth/password/forgot` (`{login}`) — always returns 200 (no user enumeration); mails a one-hour reset link. Without SMTP the mail (with the link) goes to the server log.
- `POST /api/v1/auth/password/reset` (`{token, password}`) — sets the password, revokes all sessions and refresh tokens of the user.
- `POST /api/v1/auth/email/request` (Bearer) / `POST /api/v1/auth/email/verify` (`{token}`) — 24-hour links; verifying activates `pending` accounts.
- One-time tokens are stored hashed in `one_time_tokens`.

**TOTP MFA (RFC 6238, no external deps)**
- `POST /api/v1/auth/mfa/enroll` (Bearer) → secret + `otpauth://` URL (QR is rendered in the UI); the secret is stored AES-256-GCM-encrypted.
- `POST /api/v1/auth/mfa/activate` (`{code}`) → enables MFA and returns 8 single-use recovery codes (stored hashed, shown once).
- Login becomes two-step: `POST /api/v1/auth/login` returns `{mfa_required, mfa_token}` (5-minute token that cannot be used as a Bearer token), then `POST /api/v1/auth/mfa/verify` (`{mfa_token, code}`) completes the session. Recovery codes are accepted in place of TOTP codes; wrong codes count toward the brute-force lockout.
- `POST /api/v1/auth/mfa/disable` (`{code}`).

**Groups**
- `GET/POST /api/v1/groups`, `PUT/DELETE /api/v1/groups/{id}`, `GET/POST/DELETE /api/v1/groups/{id}/roles[/{roleID}]`, `GET/POST/DELETE /api/v1/users/{id}/groups[/{groupID}]` — permissions `groups:*`.
- Permission checks now include roles inherited through groups.
- LDAP: the provider's `group_attribute` (default `memberOf`) is read at login and mapped onto SSO groups via `GET/POST/DELETE /api/v1/ldap/providers/{id}/group-mappings`; ldap-sourced memberships are re-synced on every login, manual ones are kept.

**Profile** — users gained `first_name`, `last_name`, `attributes` (JSONB), `email_verified`, `mfa_enabled`.

**UI** — new pages: forgot/reset password, email verification, `/account` (profile, email verification, MFA enrollment with QR code and recovery codes), Groups admin, LDAP group-mapping editor; login form got the second-factor step.

## Release 0.9 - Federation & Polish

Run migration `000009_federation` before starting v0.9.

**Identity brokering** — sign-in through external providers:
- Admin API `GET/POST/PUT/DELETE /api/v1/identity-providers` (permissions `identity_providers:*`). Types `google` and `github` auto-fill the endpoint URLs; `oidc` accepts any provider (authorize/token/userinfo URLs). Client secrets are stored AES-256-GCM-encrypted and never returned by the API.
- Flow: `GET /oauth2/broker/{code}/login?continue=...` → external consent → `GET /oauth2/broker/{code}/callback`. The round-trip `state` is HMAC-signed with a 10-minute TTL (CSRF protection).
- Account resolution: existing federated link → sign-in; otherwise link by email match; otherwise JIT-provision a user (`source: federated`). Local MFA is skipped for brokered logins — the second factor is the external IdP's job.
- Register the callback `{issuer}/oauth2/broker/{code}/callback` at the provider. The login page shows a "Continue with …" button per enabled provider.
- Audit: `broker_login_success/failed`, `identity_linked`, `identity_provider_*`.

**Self-service & operations**
- `POST /api/v1/auth/password/change` (Bearer; `{old_password, new_password}`) — local accounts only.
- `GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/{id}`, `DELETE /api/v1/auth/sessions` ("sign out everywhere") — own sessions.
- `POST /api/v1/oauth/clients/{id}/rotate-secret` (`oauth_clients:update`) — returns the new secret once.
- Hourly background cleanup of expired sessions, authorization codes, refresh tokens, one-time tokens and login-attempt counters.

Deferred (no consumer yet): SAML 2.0, SCIM, token exchange.

## Release 1.0 - Production Readiness

- **CI** (`.github/workflows/ci.yml`): gofmt check, `go vet`, unit tests, integration tests against a real Postgres service, golangci-lint, Vue build and Docker image build on every PR and push to main.
- **Automatic migrations**: migrations are embedded in the binary and applied on start when `SSO_MIGRATE_ON_START=true` (via golang-migrate), removing the "run migrations manually" foot-gun.
- **Integration tests** (`internal/integration`, build tag `integration`): reset schema → migrate → bootstrap → login → OAuth2 code flow with refresh rotation and reuse detection → RBAC enforcement, end-to-end over HTTP against Postgres.
- **Linting**: `.golangci.yml` (errcheck, govet, staticcheck, unused, ineffassign, gosec, misspell, unconvert), wired into CI.
- **Trusted-proxy-aware client IP**: `RealIP` middleware resolves `X-Forwarded-For` only from `SSO_TRUSTED_PROXIES`, closing the brute-force/rate-limit bypass.
- **Observability**: `/metrics` (Prometheus text format: request counts by route/status, in-flight gauge, duration sum) and `/health/version`.
- **Ops hardening**: docker-compose gained a Postgres healthcheck with `depends_on: condition`, `restart: unless-stopped`, migrate-on-start, and secrets via env interpolation instead of hardcoded values. Binary version is injected with `-ldflags -X main.version`.

## Release 1.1 - Security Hardening

Run migration `000010_hardening` before starting v1.1.

- **Revocable access tokens**: `users.tokens_invalid_before` is set on "sign out everywhere" (`DELETE /api/v1/auth/sessions`), password reset and account block/delete; `BearerAuth` rejects any access token issued at or before that moment (`token revoked`). Adds one indexed user lookup per authenticated request.
- **TOTP replay protection**: the last accepted time-step is stored in `users.mfa_last_used_counter`; a code cannot be reused within its validity window.
- **Federated login safety**: accounts are linked to an external identity only when the provider asserts a verified email (`email_verified`), and never auto-linked to an MFA-protected local account (manual linking required) — closes an account-takeover / MFA-bypass path.
- **LDAP**: empty passwords are rejected before bind, closing the LDAP "unauthenticated bind" login bypass.
- **Refresh rotation** is now race-free: rotation is a single atomic `UPDATE ... WHERE rotated_at IS NULL`; losing the race is treated as token reuse and revokes the family.
- **client_credentials** access tokens carry `purpose=client_credentials` and are refused by `BearerAuth` for this SSO's own APIs (still valid for external resource servers and introspection).
- **Uniform password policy**: minimum 12 characters everywhere (bootstrap, admin create, reset, change), max 128.
- **Wider rate limiting**: the token bucket now also covers `/api/v1/auth/mfa/verify`, `/api/v1/auth/password/forgot`, `/api/v1/auth/password/reset`, `/api/v1/auth/email/verify`, `/oauth2/revoke` and `/oauth2/introspect`.
- **Request body cap**: a 1 MiB `BodyLimit` middleware guards JSON/form endpoints against oversized-payload memory exhaustion.
- **RP-initiated logout**: `id_token_hint` is bounded to 24h by `iat` so a leaked ID token cannot drive logout indefinitely.
- **`X-Forwarded-For`**: the remaining `clientIP` helpers no longer read the header (RealIP already normalizes `RemoteAddr`), removing a latent spoofing regression.

Still a documented trade-off (not in scope here): the in-memory rate limiter and lockout counters are per-instance, so horizontal scaling needs a shared store (Redis); example configs use `sslmode=disable` and placeholder secrets that must be replaced in production.
