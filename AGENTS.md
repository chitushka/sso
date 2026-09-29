# AGENTS.md

## Fixed Stack

Backend:
- Go 1.25.0
- Docker builder image: `golang:1.25-alpine`
- PostgreSQL

Frontend:
- Vue 3
- JavaScript, not TypeScript
- Bootstrap 5
- HTML
- CSS
- Vite
- Axios
- Pinia
- Vue Router

## Development Rules

- Security first.
- Keep Clean Architecture boundaries.
- Do not introduce TypeScript.
- Do not store plain passwords, client secrets, LDAP passwords or private tokens.
- Use Argon2id for passwords and client secrets.
- Store authorization codes as hashes.
- Match redirect URI exactly.
- Public OAuth clients require PKCE S256.
- Use `gofmt` before committing.
- Single-tenant by design: do NOT add realms/multi-tenancy. One company, one global space of users, clients, roles and keys.

## Release Roadmap

- v0.1 Core
- v0.2 LDAP
- v0.3 OAuth2
- v0.3.1 Bootstrap fix
- v0.4 OIDC
- v0.5 RBAC
- v0.6 Security hardening
- v0.7 Admin UI on Vue + Bootstrap

## RBAC Development Rules

Release 0.5 introduced RBAC.

When adding a new admin API:

1. Add a permission in migration.
2. Assign it to the `admin` role.
3. Protect the route with RBAC middleware.
4. Add audit events for sensitive changes.

Do not create new unprotected admin endpoints.
## Architecture

Keep dependencies directed from transport to application/domain ports and then to infrastructure adapters:

```text
HTTP handlers/middleware -> application services -> repository interfaces
                                               <- PostgreSQL/external-service adapters
```

The composition root is `internal/app`. Domain/application packages must not depend on HTTP handlers or concrete PostgreSQL repositories. Prefer narrow, consumer-owned interfaces and cohesive services. Keep protocol behavior in `oauth`, `oidc`, `ldap`, and `broker`.

Backward compatibility with legacy behavior is not required. Remove obsolete behavior and compatibility shims when replacing them with a safer design.

## Security Invariants

- Generate opaque credentials with `crypto/rand`; store only hashes for session, refresh, authorization, password-reset and recovery tokens.
- Encrypt reversible secrets with authenticated encryption. Do not preserve plaintext fallback behavior.
- Validate token algorithm, issuer, audience/purpose, expiry and current account state as applicable.
- Password changes/resets, account blocking/deletion and sign-out-everywhere are credential revocation events.
- TOTP counters and refresh-token rotation must be consumed atomically.
- Never log credentials, authorization codes, cookies, tokens, reset/verification links, MFA secrets, or sensitive request bodies.
- Trust forwarding headers only from `SSO_TRUSTED_PROXIES` and strip them before downstream handlers.
- Production requires an HTTPS issuer, independent non-placeholder secrets, PostgreSQL TLS and configured SMTP.
- Outbound HTTP, SMTP and LDAP calls require context cancellation and finite timeouts.
- Keep request body/header limits and HTTP read/write/idle timeouts.

## Configuration Rules

- Use only the `SSO_` namespace.
- Add a setting only when deployments genuinely need to vary it.
- Prefer secure unconditional behavior over security feature flags.
- Validate configuration at startup and fail closed.
- Keep `.env.example`, Docker Compose, README and `internal/config` synchronized.
- Do not add aliases for removed or legacy variables.

## Database Rules

- Schema changes use ordered up/down migrations.
- Security-sensitive read/modify/write operations must be atomic in PostgreSQL.
- Do not edit an already released migration when a new forward migration is required.

## Quality Gates

Before recording a change:

- Run `gofmt` on changed Go files.
- Run `go test ./...` and `go vet ./...`.
- Run integration tests when PostgreSQL is available.
- Run `govulncheck ./...` for dependency or security changes.
- For frontend changes run `npm ci`, `npm audit --omit=dev`, and `npm run build`.
- Run `git diff --check`.
- Keep this file current when architecture, security invariants, stack, configuration or required checks change.
