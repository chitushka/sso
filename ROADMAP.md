# ROADMAP.md

## v0.4 — OpenID Connect

Status: generated for testing.

Scope:
- OIDC Discovery
- JWKS
- ID Token
- UserInfo
- nonce
- RSA 2048 / RS256

## v0.5 — RBAC

Status: generated for testing.

Scope:
- roles
- permissions
- user-role assignments
- role-permission assignments
- bootstrap admin role
- authorization middleware

## v0.5.1 — Configuration Refactoring

Status: done.

Scope:
- standardize application variables under the `SSO_` namespace
- replace `SSO_DB_URL` with `SSO_DATABASE_URL`
- introduce typed configuration groups for HTTP, database, security, tokens, CORS, OIDC and logging
- validate required database and JWT configuration at startup
- update Docker Compose and documentation examples

## v0.5.2 — Security Fixes

Status: done.

Scope:
- verify confidential client secret at the token endpoint (`client_secret_basic` and `client_secret_post`)
- enforce requested scope against client `allowed_scopes`
- encrypt LDAP bind passwords at rest (AES-256-GCM, `SSO_ENCRYPTION_KEY`)
- background OIDC signing key rotation behind `SSO_OIDC_KEY_ROTATION_ENABLED`
- configuration parse errors are returned instead of panicking

## v0.6 — Security Hardening

Status: done.

Scope:
- refresh tokens with rotation and reuse detection (family revocation)
- token revocation (RFC 7009) and introspection (RFC 7662) endpoints
- brute force protection with exponential lockout per (username, IP)
- rate limiting on login, token and bootstrap endpoints
- audit log read API (`audit:read` permission)
- completed admin CRUD: delete users, update/delete roles, OAuth clients and LDAP providers
- secret encryption delivered early in v0.5.2 (`SSO_ENCRYPTION_KEY`)

## v0.6.5 — OIDC Completeness

Status: done.

Scope:
- RP-initiated logout (`/oauth2/logout`, end_session_endpoint) with `id_token_hint`, registered `post_logout_redirect_uris` and session + refresh token revocation
- back-channel logout (signed `logout_token` POSTed to the client's `backchannel_logout_uri`)
- consent flow: `user_consents` storage, `consent_required` from authorize, `GET/POST /oauth2/consent`, `skip_consent` for trusted clients
- `client_credentials` grant for service accounts (confidential clients only)
- UserInfo claims filtered by token scope
- RFC 6749 error format (`error` + `error_description`) on all `/oauth2/*` endpoints
- `GET /api/v1/oauth/clients/{id}`

## v0.7 — Admin UI

Status: done.

Stack:
- Vue 3 + Vite (JavaScript, no TypeScript)
- Bootstrap 5
- Pinia, Vue Router, Axios

Scope:
- SPA in `web/admin/`, served by the Go binary from `web/admin/dist` (SPA fallback routing)
- pages: sign-in, dashboard, users + role assignment, roles + permission assignment, OAuth clients (one-time secret display), LDAP providers + connection test, audit log with filters
- OAuth consent page wired to `GET/POST /oauth2/consent`
- login supports `?continue=` redirect back into `/oauth2/authorize` flows
- Docker multi-stage build with a Node UI stage

## v0.8 — Accounts & MFA (planned)

- SMTP mailer, password reset, email verification
- TOTP MFA with recovery codes
- groups and composite roles, LDAP group-to-role mapping
- extended user profile (name, attributes)
