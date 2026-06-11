# SSO

Production-ready SSO / IAM service written in Go.

Current release: **0.3 - OAuth2 Authorization Server**.

## Stack

- Go 1.25
- PostgreSQL
- Redis-ready architecture
- REST API
- Argon2id
- JWT
- LDAP / Active Directory Search + Bind
- OAuth2 Authorization Code Flow
- Docker Compose

## Releases

### Release 0.1 - Core

- Configuration loader
- PostgreSQL connection
- Health checks
- Local users
- Argon2id password hashing
- Login / logout
- Server-side sessions
- JWT access token
- Audit log
- Basic users API

### Release 0.2 - LDAP

- LDAP provider CRUD
- Active Directory compatible Search + Bind
- LDAP connection test endpoint
- LDAP shadow users
- LDAP login fallback after local auth failure
- LDAP audit events
- OpenLDAP service in Docker Compose

### Release 0.3 - OAuth2

- OAuth client CRUD
- Confidential and public clients
- Exact redirect URI validation
- Authorization Code Flow
- PKCE S256 for public clients
- One-time authorization codes
- Hashed authorization code storage
- Token endpoint for `authorization_code`
- JWT OAuth2 access tokens with `client_id` and `scope`
- OAuth audit events

## Run

```bash
docker compose up --build
```

API:

```text
http://localhost:8080
```

## Migrations

Migrations are stored in `migrations/`.

```text
000001_init
000002_ldap
000003_oauth
```

## OAuth2 Example

### 1. Create local admin/user and login

Use existing Release 0.1 endpoints:

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

The response returns `access_token` and sets `sso_session` cookie.

### 2. Create OAuth client

```http
POST /api/v1/oauth/clients
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "client_id": "app1",
  "name": "Application 1",
  "type": "confidential",
  "redirect_uris": ["http://localhost:9000/callback"],
  "allowed_scopes": ["read", "profile"]
}
```

For confidential clients the response includes `client_secret` once. Store it securely.

For public clients use:

```json
{
  "client_id": "spa",
  "name": "SPA",
  "type": "public",
  "redirect_uris": ["http://localhost:5173/callback"],
  "allowed_scopes": ["read", "profile"]
}
```

### 3. Authorize

```http
GET /oauth2/authorize?response_type=code&client_id=app1&redirect_uri=http://localhost:9000/callback&scope=read%20profile&state=abc
Cookie: sso_session=<session_cookie>
```

Successful response:

```http
302 Location: http://localhost:9000/callback?code=<code>&state=abc
```

### 4. Exchange code

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(app1:client_secret)

grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:9000/callback
```

Response:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read profile"
}
```

## PKCE for public clients

Public clients must use PKCE S256.

Authorize request must include:

```text
code_challenge=<base64url(sha256(code_verifier))>
code_challenge_method=S256
```

Token request must include:

```text
code_verifier=<original verifier>
```

## Security Notes

- Passwords are hashed with Argon2id.
- LDAP passwords are never stored.
- OAuth authorization codes are stored only as SHA-256 hashes.
- Client secrets are stored as Argon2id hashes.
- Redirect URI matching is exact.
- Public clients require PKCE S256.
- Access tokens are JWT signed with HS256 in Release 0.3.

## Next Release

Release 0.4 will add OpenID Connect:

- Discovery endpoint
- JWKS endpoint
- ID Token
- UserInfo endpoint
- OIDC scopes and claims

## Release 0.3.1 - Bootstrap Admin Fix

This patch separates first-run initialization from the regular user management API.

### Bootstrap status

```bash
curl http://localhost:8080/api/v1/bootstrap/status
```

Response before initialization:

```json
{
  "initialized": false
}
```

Response after at least one user exists:

```json
{
  "initialized": true
}
```

### Create the first administrator

```bash
curl -X POST http://localhost:8080/api/v1/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "StrongPassword123"
  }'
```

Rules:

- The endpoint works only while the `users` table is empty.
- Password must contain at least 12 characters.
- The created user has `source=local` and `status=active`.
- After the first user has been created, repeated bootstrap calls return `409 Conflict`.

### Regular user creation

`POST /api/v1/users` no longer contains bootstrap logic. It is a regular administrative endpoint protected by Bearer authentication.

### Fixed in this patch

- Removed one-shot bootstrap behavior from `internal/users/handler.go`.
- Added `internal/bootstrap` package.
- Added `GET /api/v1/bootstrap/status`.
- Added `POST /api/v1/bootstrap`.
- Fixed LDAP service composition in `internal/app/app.go` by passing `ldap.NewClient()` to `ldap.NewService(...)`.
- Added bootstrap unit tests.
