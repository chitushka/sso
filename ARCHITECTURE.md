# ARCHITECTURE.md

# System Overview

The system is a centralized Identity Provider (IdP).

Responsibilities:

- Authentication
- Authorization
- User Management
- Session Management
- Token Issuing
- Audit Logging

Not responsible for:

- Business logic of client applications
- Application-specific data

---

# Architecture Style

Clean Architecture

Layers:

Transport
↓
Application
↓
Domain
↓
Repository
↓
Storage

Dependencies only point inward.

---

# Directory Structure

cmd/
api/
worker/

internal/
app/
auth/
audit/
config/
crypto/
domain/
middleware/
permissions/
roles/
sessions/
storage/
transport/
users/

migrations/

web/

deployments/

tests/

---

# Core Domains

## User

Represents system identity.

Attributes:

- username
- email
- password hash
- status
- source

Sources:

- local
- ldap

---

## Session

Represents authenticated session.

Contains:

- user id
- ip
- user agent
- expiration

Supports revocation.

---

## Role

Collection of permissions.

---

## Permission

Action that can be performed.

Examples:

users:create
users:update
users:delete

---

# Authentication

Current:

Local Authentication

Future:

LDAP
OAuth2
OIDC
MFA

---

# Authorization

Primary model:

RBAC

User
→ Role
→ Permission

Future:

ABAC

---

# Multi-Tenancy

Future requirement.

Every new module must be designed so tenant_id can be introduced without redesign.

Current default:

single tenant

Future:

multi tenant

---

# Database

Primary:

PostgreSQL

Secondary:

Redis

---

# Session Storage

Current:

PostgreSQL

Future:

Redis-backed session cache.

---

# Token Strategy

Current:

Session based

Future:

JWT

Access Token
Refresh Token
ID Token

---

# LDAP Strategy

Use Search + Bind.

Flow:

1. Bind with service account
2. Search user
3. Bind as user
4. Sync profile

Never store LDAP passwords.

---

# Frontend Architecture

Vue 3

Structure:

src/
api/
components/
layouts/
pages/
router/
stores/

Bootstrap 5 layout.

---

# Security Requirements

Mandatory:

- secure cookies
- audit logging
- brute force protection
- password policies
- token revocation
