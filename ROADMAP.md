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

Status: in progress.

Scope:
- standardize application variables under the `SSO_` namespace
- replace `SSO_DB_URL` with `SSO_DATABASE_URL`
- introduce typed configuration groups for HTTP, database, security, tokens, CORS, OIDC and logging
- validate required database and JWT configuration at startup
- update Docker Compose and documentation examples

## v0.6 — Security Hardening

Planned:
- rate limiting
- brute force protection
- refresh token rotation
- secret encryption
- stricter audit policy

## v0.7 — Admin UI

Stack:
- Vue 3
- JavaScript
- Bootstrap 5
- HTML
- CSS
