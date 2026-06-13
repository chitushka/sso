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
- `rbac` — roles, permissions and administrative access control
- `audit` — audit events
- `config` — typed application configuration loaded from `SSO_` environment variables

## Configuration Architecture

Release 0.5.1 uses a typed configuration model:

```text
Config
  Env
  HTTP.Address
  Database.URL
  Security.JWTSecret
  Token.AccessTTL
  Token.SessionTTL
  CORS.AllowedOrigins
  OIDC.Issuer
  Logging.Level
```

Application configuration must use the `SSO_` environment namespace. The canonical database variable is `SSO_DATABASE_URL`.

## OIDC

v0.4 uses RSA 2048 keys and RS256. Active signing keys are stored in PostgreSQL and exposed through JWKS.

## Frontend decision

Admin UI must use Vue 3 + Bootstrap 5 + JavaScript, HTML, CSS. TypeScript is intentionally excluded.

## RBAC Architecture

Release 0.5 introduces RBAC as the primary authorization model.

```text
User -> UserRole -> Role -> RolePermission -> Permission
```

Permissions are resource/action pairs:

```text
users:create
ldap:test
oauth_clients:create
```

Authorization is enforced in HTTP middleware after JWT authentication. Domain services remain independent from HTTP middleware and can still be tested directly.
