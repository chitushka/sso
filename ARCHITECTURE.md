# ARCHITECTURE.md

The project is a production-oriented SSO and Identity Provider.

## Layers

Transport -> Application -> Domain -> Repository -> Storage

## Current modules

- `auth` — local login, sessions, JWT access tokens
- `bootstrap` — first admin initialization
- `users` — user management
- `ldap` — LDAP provider configuration and Search + Bind authentication
- `oauth` — OAuth2 clients, authorization codes and token endpoint
- `oidc` — discovery, JWKS, ID token and UserInfo
- `audit` — audit events

## OIDC

v0.4 uses RSA 2048 keys and RS256. Active signing keys are stored in PostgreSQL and exposed through JWKS.

## Frontend decision

Admin UI must use Vue 3 + Bootstrap 5 + JavaScript, HTML, CSS. TypeScript is intentionally excluded.
