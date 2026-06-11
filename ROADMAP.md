# ROADMAP.md

## Release 0.1 - Core

Status: completed

- Configuration
- PostgreSQL
- Local users
- Argon2id passwords
- Sessions
- Audit log
- REST API
- Docker support

## Release 0.2 - LDAP

Status: completed / under testing

- LDAP providers
- Active Directory compatible Search + Bind
- LDAP connection test
- LDAP shadow users
- LDAP login fallback

## Release 0.3 - OAuth2 Authorization Server

Status: completed / under testing

- OAuth clients
- Authorization Code Flow
- PKCE S256
- `/oauth2/authorize`
- `/oauth2/token`
- JWT access token

## Release 0.3.1 - Bootstrap Admin Fix

Status: completed

- Moved first-admin bootstrap from users API to dedicated bootstrap module.
- Added `GET /api/v1/bootstrap/status`.
- Added `POST /api/v1/bootstrap`.
- Fixed LDAP service dependency injection in app composition root.

## Release 0.4 - OpenID Connect

Planned:

- Discovery endpoint
- JWKS endpoint
- ID Token
- UserInfo endpoint
- OIDC claims mapping

## Release 0.5 - RBAC

Planned:

- Roles
- Permissions
- User-role assignment
- Role-permission assignment
- Admin-only user management
- Bootstrap creates default admin role and assigns it to first admin
