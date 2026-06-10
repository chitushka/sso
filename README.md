# SSO

Production-ready SSO / Identity Provider written in Go.

Current release: `0.2`.

## Stack

- Go 1.25
- PostgreSQL
- Redis-ready architecture
- Argon2id password hashing
- JWT access tokens
- Server-side sessions
- LDAP / Active Directory authentication
- Docker Compose

## Run locally

```bash
docker compose up --build
```

API:

```text
http://localhost:8080
```

Health checks:

```bash
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
```

## Release 0.1 Core

Implemented:

- configuration loader
- PostgreSQL connection
- migrations
- local users
- Argon2id password hashing
- login/logout
- JWT access token issuing
- server-side sessions
- audit log
- protected users API

## Release 0.2 LDAP

Implemented:

- LDAP provider model
- LDAP provider CRUD API
- LDAP connection test endpoint
- LDAP Search + Bind authentication
- local-auth first, LDAP fallback login flow
- shadow-user synchronization into `users`
- LDAP audit events
- Docker Compose OpenLDAP service for local testing

LDAP passwords are never stored on local users. Service account bind password is currently stored in DB as plain text for development; Release 0.6 must replace this with encrypted secrets.

## API

### Auth

```http
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

### Users

Protected by bearer token.

```http
GET  /api/v1/users
POST /api/v1/users
GET  /api/v1/users/{id}
PUT  /api/v1/users/{id}
POST /api/v1/users/{id}/password
```

### LDAP Providers

Protected by bearer token.

```http
GET    /api/v1/ldap/providers
POST   /api/v1/ldap/providers
GET    /api/v1/ldap/providers/{id}
PUT    /api/v1/ldap/providers/{id}
DELETE /api/v1/ldap/providers/{id}
POST   /api/v1/ldap/providers/{id}/test
```

Example LDAP provider for the local OpenLDAP container:

```json
{
  "name": "local-openldap",
  "host": "ldap",
  "port": 389,
  "use_tls": false,
  "start_tls": false,
  "bind_dn": "cn=admin,dc=example,dc=org",
  "bind_password": "admin",
  "base_dn": "dc=example,dc=org",
  "user_filter": "(&(objectClass=inetOrgPerson)(uid={username}))",
  "username_attribute": "uid",
  "email_attribute": "mail",
  "display_name_attribute": "cn",
  "enabled": true
}
```

## LDAP authentication flow

```text
1. User submits username/password to /api/v1/auth/login
2. SSO checks local user credentials first
3. If local authentication does not match, SSO tries enabled LDAP providers
4. LDAP provider performs service account bind
5. LDAP provider searches user by configured filter
6. LDAP provider binds as found user DN using submitted password
7. SSO creates or updates local shadow user
8. SSO creates server-side session and JWT access token
```

## Security notes

Current development limitations:

- LDAP bind password is not encrypted yet
- rate limiting is not implemented yet
- MFA is not implemented yet
- OAuth2/OIDC are planned for later releases

Do not expose this release to production traffic without Release 0.6 security hardening.
