# SSO v0.4 — OpenID Connect Provider

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

## Start

```bash
docker compose build
docker compose up
```

Run migrations manually with your preferred migration tool. Migration files are in `migrations/`.

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

## Release 0.4 scope

- OIDC Discovery
- JWKS endpoint
- RSA 2048 / RS256 signing
- ID Token
- UserInfo endpoint
- nonce support
- Bootstrap fix
- LDAP DI fix
- Go 1.25.0 baseline

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

Run migrations before testing v0.5.
