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

Planned:
- roles
- permissions
- user-role assignments
- role-permission assignments
- bootstrap admin role
- authorization middleware

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

## Release 0.5 - RBAC

Status: GENERATED

Implemented:

- roles table
- permissions table
- role_permissions table
- user_roles table
- default admin/user roles
- default permission set
- RBAC middleware
- role API
- permission API
- user-role assignment API
- bootstrap admin role assignment
- permission checks for users, LDAP provider and OAuth client admin APIs
