# chitushka/sso

Release 0.1 Core: базовая production-oriented версия SSO-сервиса на Go.

## Что реализовано

- HTTP API на Go + chi.
- PostgreSQL через pgxpool.
- Конфигурация через environment variables / `.env`.
- Миграция БД `000001_init`.
- Локальные пользователи.
- Argon2id hashing для паролей.
- Login/logout.
- JWT access token.
- HttpOnly session cookie.
- `/api/v1/auth/me`.
- Basic admin API пользователей.
- Audit log для login/user_created.
- Health endpoints.
- Dockerfile и docker-compose.

## Запуск

```bash
cp .env.example .env
docker compose up --build
```

Проверка:

```bash
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
```

## Создание первого пользователя

Пока таблица `users` пустая, доступен одноразовый bootstrap endpoint:

```bash
curl -X POST http://localhost:8080/api/v1/bootstrap/admin \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@example.com","password":"change-me-123456"}'
```

После создания первого пользователя endpoint начинает возвращать `409 Conflict`.

## Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password"}'
```

Ответ содержит:

- `access_token`
- `session_token`
- `user`

## Дальнейшие этапы

Release 0.2:

- LDAP / Active Directory provider.
- LDAP Search + Bind.
- Shadow users.
- LDAP group mapping.

Release 0.3:

- OAuth2 Authorization Code Flow.
- Clients.
- Authorization codes.
- Token endpoint.
- Refresh tokens.

Release 0.4:

- OIDC discovery.
- ID Token.
- JWKS.
- UserInfo.

## API

### Health

```text
GET /health/live
GET /health/ready
```

### Auth

```text
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

### Users

All `/api/v1/users/*` endpoints require:

```text
Authorization: Bearer <access_token>
```

```text
GET  /api/v1/users
POST /api/v1/users
GET  /api/v1/users/{id}
PUT  /api/v1/users/{id}
POST /api/v1/users/{id}/password
```

## Важные замечания

Это Release 0.1 Core. Он уже имеет нормальную структуру и безопасное хранение паролей, но ещё не является полноценным SSO в смысле OAuth2/OIDC. Протокольная часть будет добавляться в следующих релизах.
