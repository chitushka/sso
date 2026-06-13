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
