# SSO — единый вход и поставщик удостоверений

Готовый к эксплуатации SSO/IdP на Go для одной организации. Система предоставляет локальную и LDAP-аутентификацию, OAuth 2.0, OpenID Connect, RBAC, MFA, федеративный вход и административную панель.

Мультитенантность и realms намеренно не поддерживаются: пользователи, клиенты, роли и ключи находятся в едином глобальном пространстве.

## Возможности

- локальная аутентификация, серверные сессии, подтверждение email и восстановление пароля;
- LDAP/Active Directory Search + Bind и сопоставление групп;
- OAuth 2.0 Authorization Code, Refresh Token и Client Credentials;
- OIDC Discovery, JWKS, ID Token, UserInfo, consent и RP/back-channel logout;
- обязательный PKCE S256 для публичных клиентов;
- роли, разрешения, группы и аудит;
- TOTP MFA и коды восстановления;
- вход через Google, GitHub и произвольных OIDC-провайдеров;
- административная SPA на Vue 3 и Bootstrap 5;
- health checks, метрики Prometheus, встроенные миграции и интеграционные тесты.

## Стек

- Go 1.26.10, образ сборщика `golang:1.26.10-alpine`; ветка Go 1.26 зафиксирована для разработки и не должна заменяться другой minor- или major-версией;
- PostgreSQL;
- Vue 3, JavaScript, Vite 8, Bootstrap 5, Pinia 4, Vue Router 5 и Axios;
- Docker и Docker Compose.

## Архитектура

Зависимости направлены от транспорта к приложению и доменным портам, затем — к инфраструктурным адаптерам:

```text
HTTP-обработчики/middleware -> сервисы приложения -> интерфейсы репозиториев
                                                  <- PostgreSQL/внешние сервисы
```

Корень композиции расположен в `internal/app`. Доменные и прикладные пакеты не зависят от HTTP-обработчиков или конкретных PostgreSQL-репозиториев. Протокольная логика находится в `oauth`, `oidc`, `ldap` и `broker`.

Основные модули:

- `auth` — локальный вход, сессии и токены;
- `bootstrap` — создание первого администратора;
- `users` — пользователи и профили;
- `ldap` — LDAP и Search + Bind;
- `oauth` — клиенты, коды авторизации и token endpoint;
- `oidc` — Discovery, JWKS, ID Token и UserInfo;
- `rbac` — роли, разрешения, группы и доступ;
- `audit` — аудит;
- `broker` — внешние поставщики удостоверений;
- `config` — типизированная конфигурация из переменных `SSO_`.

Модель доступа:

```text
Пользователь -> Роль -> Разрешение
Пользователь -> Группа -> Роль -> Разрешение
```

Разрешения — пары ресурс/действие, например `users:create`, `ldap:test`, `oauth_clients:update`. Доступ после аутентификации проверяет HTTP middleware; сервисы приложения остаются независимыми от HTTP.

Токены подписываются ключами RSA 2048/RS256. Открытые активные и выводимые из обращения ключи публикуются через JWKS, закрытые ключи хранятся в PostgreSQL зашифрованными.

## Быстрый запуск

```bash
docker compose build
docker compose up
```

`docker-compose.yml` предназначен только для разработки: он публикует PostgreSQL и LDAP и использует временные учётные данные.

Служебные маршруты:

- `GET /health/live` — процесс работает;
- `GET /health/ready` — база доступна и миграции актуальны;
- `GET /health/version` — версия;
- `GET /metrics` — метрики, требуется `metrics:read`.

## Развёртывание в production

Приложение принимает HTTP и должно работать за reverse proxy с завершением TLS.

```bash
cp .env.production.example .env.production
# Заполните значения и замените SSO_IMAGE на неизменяемый digest.
docker network create production-edge
docker compose --env-file .env.production -f docker-compose.prod.yml up -d
```

`docker-compose.prod.yml` запускает hardened-контейнер: корневая файловая система доступна только для чтения, capabilities удалены, порты хоста не публикуются.

Требования:

- завершайте HTTPS на доверенном proxy и передавайте запросы на `:8080`;
- укажите IP/CIDR proxy в `SSO_TRUSTED_PROXIES` и устанавливайте `X-Forwarded-Proto: https`;
- используйте PostgreSQL с `sslmode=require`, `verify-ca` или предпочтительно `verify-full`;
- подключайте LDAP через LDAPS или StartTLS;
- храните секреты в хранилище оркестратора или защищённом env-файле;
- используйте разные `SSO_JWT_SECRET` и `SSO_ENCRYPTION_KEY` длиной не менее 32 символов;
- настройте SMTP с STARTTLS и HTTPS issuer.

`X-Forwarded-For` учитывается только от узлов из `SSO_TRUSTED_PROXIES`; после нормализации все обработчики читают IP только из `RemoteAddr`. Входящий `X-Request-ID` принимается лишь в безопасном ASCII-формате длиной до 64 символов, иначе сервер генерирует UUID. Встроенные миграции применяются при `SSO_MIGRATE_ON_START=true`; для поэтапного развёртывания применяйте файлы из `migrations/` отдельным заданием.

## Конфигурация

Поддерживается только пространство имён `SSO_`. Устаревшие `DATABASE_URL`, `SSO_DB_URL`, `JWT_SECRET`, `ACCESS_TOKEN_TTL` и `SESSION_TTL` не принимаются.

| Переменная | Обязательность | Назначение |
| --- | --- | --- |
| `SSO_ENV` | нет | Среда выполнения |
| `SSO_HTTP_ADDR` | нет | Адрес HTTP-сервера, обычно `:8080` |
| `SSO_DATABASE_URL` | да | Подключение PostgreSQL; в production нужен TLS |
| `SSO_MIGRATE_ON_START` | нет | Применять миграции при запуске |
| `SSO_TRUSTED_PROXIES` | нет | IP/CIDR доверенных proxy через запятую |
| `SSO_JWT_SECRET` | да | HMAC-секрет состояния broker, не менее 32 символов |
| `SSO_ENCRYPTION_KEY` | да | Ключ AES-256-GCM, не менее 32 символов |
| `SSO_ACCESS_TOKEN_TTL` | нет | Срок access-токена, обычно `15m` |
| `SSO_SESSION_TTL` | нет | Срок сессии, обычно `720h` |
| `SSO_REFRESH_TOKEN_TTL` | нет | Срок refresh-токена |
| `SSO_CORS_ALLOWED_ORIGINS` | нет | Разрешённые origins через запятую |
| `SSO_ISSUER` | нет | Issuer OAuth 2.0/OIDC |
| `SSO_LOG_LEVEL` | нет | `debug`, `info`, `warn` или `error` |
| `SSO_SMTP_HOST`, `SSO_SMTP_PORT` | production | SMTP-сервер и порт |
| `SSO_SMTP_USERNAME`, `SSO_SMTP_PASSWORD` | нет | Учётные данные SMTP |
| `SSO_SMTP_FROM` | для SMTP | Адрес отправителя |
| `SSO_SMTP_STARTTLS` | production | Должен быть `true` |

Production-проверка отклоняет незашифрованный PostgreSQL, SMTP без STARTTLS, незащищённый LDAP, HTTP issuer, одинаковые или шаблонные секреты и отсутствующий SMTP.

### Ротация `SSO_ENCRYPTION_KEY`

1. Сделайте резервную копию PostgreSQL, остановите API и примените миграции.
2. Оставьте текущий ключ в `SSO_ENCRYPTION_KEY`, новый передайте через `SSO_NEW_ENCRYPTION_KEY`.
3. Выполните `/app/sso-api rotate-encryption-key`.
4. После успеха замените основной ключ, удалите новую переменную и запустите API.

Операция атомарно перешифровывает секреты. При ошибке транзакция откатывается. Нельзя одновременно запускать экземпляры со старым и новым ключами.

## Первый администратор и вход

```http
GET  /api/v1/bootstrap/status
POST /api/v1/bootstrap
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

```json
{
  username: admin,
  email: admin@example.com,
  password: StrongPassword123
}
```

Первому пользователю назначается роль `admin`. Пароль содержит 12–128 символов. Панель использует HttpOnly cookie и CSRF-защиту; Bearer-токены не хранятся в browser storage.

## OAuth 2.0 и OpenID Connect

```http
GET      /.well-known/openid-configuration
GET      /.well-known/jwks.json
GET      /oauth2/userinfo
GET      /oauth2/authorize
POST     /oauth2/token
POST     /oauth2/revoke
POST     /oauth2/introspect
GET/POST /oauth2/logout
GET/POST /oauth2/consent
```

Ошибки `/oauth2/*` соответствуют RFC 6749: `{error:...,error_description:...}`.

Refresh-токены одноразовые и ротируются. Повторное использование старого токена отзывает всю семью. Конфиденциальные клиенты используют `client_secret_basic` или `client_secret_post`; публичные — PKCE S256.

Access-токены RS256 содержат `kid`, `iss`, `aud`, `exp`, `iat` и `token_type`. Блокировка или удаление пользователя атомарно устанавливает `tokens_invalid_before`, отзывает все сессии, refresh-токены и неиспользованные authorization codes, после чего немедленно очищается локальный кэш состояния доступа. Конкурентная выдача сессии или refresh-токена синхронизирована со сменой статуса пользователя. Разблокировка не восстанавливает старые полномочия, а восстановление удалённой записи через общий update API запрещено. Смена или сброс пароля и выход на всех устройствах также отзывают пользовательские полномочия. Токены `client_credentials` не принимаются административным API.

## Учётные записи и безопасность

Локальный пользователь со статусом `pending` при создании получает одноразовую ссылку подтверждения по email. Пользователь активируется только после `POST /api/v1/auth/email/verify`. Если письмо потеряно, публичный `POST /api/v1/auth/email/resend` принимает поле `login` и всегда возвращает одинаковый успешный ответ, не раскрывая наличие учётной записи. Повторная отправка доступна не чаще одного раза в минуту; новая ссылка атомарно аннулирует прежние.

- Одноразовые ссылки и refresh-токены хранятся только в виде хешей.
- TOTP соответствует RFC 6238; секрет зашифрован, коды восстановления хешируются.
- Принятый TOTP-код нельзя использовать повторно.
- Поиск, JIT provisioning и связывание внешнего subject выполняются одной транзакцией с блокировкой. Внешняя учётная запись связывается только по подтверждённому непустому email и не связывается автоматически с локальной записью с MFA. Для GitHub используется только primary verified email из `/user/emails`.
- Серверные запросы identity broker и OIDC back-channel разрешены только к публичным IP-адресам: проверяются все DNS-ответы и фактический адрес соединения, proxy и redirects отключены. Внутренние, loopback, link-local, зарезервированные и IPv6-адреса с зоной отклоняются без настраиваемого обхода.
- LDAP dial, TLS/StartTLS, bind и search ограничены единым тайм-аутом 10 секунд. Более короткий deadline входящего контекста имеет приоритет, а его отмена немедленно закрывает соединение и прерывает текущую LDAP-операцию.
- LDAP bind password хранится только в зашифрованном виде и никогда не возвращается административным API; пустое значение при обновлении сохраняет существующий секрет.
- Пустые пароли отклоняются до LDAP bind.
- Ошибки входа учитываются в PostgreSQL по паре «пользователь, IP» с экспоненциальной блокировкой.
- Чувствительные маршруты защищены двумя token bucket: общим состоянием в PostgreSQL для всех экземпляров и дополнительным локальным слоем. Локальный слой ограничен 10 000 ключами и использует амортизированное O(1) LRU/TTL-вытеснение; ключи в PostgreSQL хранятся как SHA-256. При недоступности общего хранилища защита работает fail-closed и возвращает `503 Service Unavailable` с `Retry-After`. Метрики `sso_rate_limit_local_buckets` и `sso_rate_limit_local_evictions_total` показывают размер локального состояния и вытеснения по TTL/ёмкости.
- Тела запросов ограничены 1 МиБ, секреты и токены не журналируются.
- Ответы с токенами, authorization code, client secret, MFA-секретом, recovery-кодами или browser-сессией содержат `Cache-Control: no-store` и `Pragma: no-cache`.
- Аудит: `GET /api/v1/audit?actor=&action=&from=&to=&limit=&offset=`, разрешение `audit:read`. Обязательные события `security.*` создаются триггерами PostgreSQL в одной транзакции с изменением: ошибка записи аудита откатывает мутацию. Они содержат только тип операции и безопасные идентификаторы, без секретов. Более подробные прикладные события с пользователем, IP-адресом и User-Agent являются best-effort телеметрией и не меняют результат уже завершённой операции.

## Административная панель

SPA находится в `web/admin/`. Интерфейс использует единый словарь `vue-i18n` и русский язык по умолчанию; протокольные идентификаторы и технические значения не переводятся. В production SPA собирается в Docker и обслуживается Go-бинарником из `web/admin/dist`. Без `dist` сервер работает только как API.

```bash
cd web/admin
npm ci
npm run dev
```

Vite работает на `:5173` и проксирует API на `:8080`. Версия продукта едина для API и SPA: Docker build argument `VERSION` передаётся в Go через `ldflags`, а во frontend — как `VITE_APP_VERSION`; версия приватного npm-пакета не используется как версия продукта.

## Как подключить приложение к SSO

В примерах приложение `hello_sso` работает на `https://hello-sso.example.com`, а SSO — на `https://sso.example.com`. Подставьте реальные адреса.

### 1. Зарегистрируйте OAuth-клиента

В панели откройте **OAuth-клиенты**, нажмите **Новый клиент** и заполните:

| Поле | Пример | Пояснение |
| --- | --- | --- |
| `client_id` | `hello_sso` | Уникальный идентификатор |
| Название | `Hello SSO Demo App` | Отображаемое имя |
| Тип | `confidential` | `confidential` для backend, `public` для SPA или мобильного приложения |
| Разрешённые scope | `openid profile email` | Разрешённые области доступа |
| Redirect URI | `https://hello-sso.example.com/auth/callback` | Точный адрес возврата |
| Post-logout redirect URI | `https://hello-sso.example.com/` | Адрес после выхода |
| Back-channel logout URI | пусто | Необязательный серверный callback |
| Не запрашивать согласие | выключено | Только для доверенных приложений |
| Включён | включено | Клиент активен |

`client_secret` показывается один раз. Храните его в менеджере секретов или серверном env-файле, не помещайте во frontend или Git.

`openid` включает OIDC и ID Token, `profile` разрешает имя и источник учётной записи, `email` — почту. Запрос неразрешённого scope вернёт `invalid_scope`.

### 2. Настройте библиотеку OIDC

Используйте Discovery document `https://sso.example.com/.well-known/openid-configuration`.

- issuer: `https://sso.example.com`;
- authorization: `https://sso.example.com/oauth2/authorize`;
- token: `https://sso.example.com/oauth2/token`;
- UserInfo: `https://sso.example.com/oauth2/userinfo`;
- JWKS: `https://sso.example.com/.well-known/jwks.json`.

### 3. Выполните Authorization Code Flow

```text
https://sso.example.com/oauth2/authorize
  ?response_type=code
  &client_id=hello_sso
  &redirect_uri=https://hello-sso.example.com/auth/callback
  &scope=openid profile email
  &state=СЛУЧАЙНАЯ_СТРОКА
```

Сохраните криптографически случайный `state` в сессии и сравните после возврата — это защита от CSRF. Пароль и MFA пользователь вводит только на SSO. После согласия браузер вернётся на:

```text
https://hello-sso.example.com/auth/callback?code=ОДНОРАЗОВЫЙ_КОД&state=ТА_ЖЕ_СТРОКА
```

Проверьте `state` и обменяйте код с сервера приложения:

```bash
curl -X POST https://sso.example.com/oauth2/token \
  -d grant_type=authorization_code \
  -d code=ОДНОРАЗОВЫЙ_КОД \
  -d redirect_uri=https://hello-sso.example.com/auth/callback \
  -d client_id=hello_sso \
  -d client_secret=ВАШ_CLIENT_SECRET
```

Ответ содержит `access_token`, `id_token`, `refresh_token`, `token_type` и `expires_in`. Проверяйте ID Token через Discovery/JWKS. Используйте claim `sub` как идентификатор пользователя.

Профиль можно запросить через `GET /oauth2/userinfo` с заголовком `Authorization: Bearer ВАШ_ACCESS_TOKEN`.

### 4. Обновляйте токены и выполняйте выход

Для обновления отправьте `POST /oauth2/token` с `grant_type=refresh_token`, последним `refresh_token` и учётными данными клиента. Атомарно сохраняйте новый refresh-токен: старый после обмена недействителен.

Для выхода перенаправьте браузер:

```text
https://sso.example.com/oauth2/logout
  ?id_token_hint=ПОСЛЕДНИЙ_ID_TOKEN
  &post_logout_redirect_uri=https://hello-sso.example.com/
```

`post_logout_redirect_uri` должен посимвольно совпадать с зарегистрированным адресом.

### Публичные приложения и PKCE

Для SPA и мобильных приложений создайте клиента типа `public`; секрет ему не нужен.

1. Сгенерируйте `code_verifier` длиной 43–128 символов.
2. Вычислите `code_challenge = BASE64URL(SHA256(code_verifier))`.
3. Передайте `code_challenge` и `code_challenge_method=S256` при авторизации.
4. При обмене кода передайте `code_verifier` вместо `client_secret`.

Готовые OIDC-библиотеки обычно выполняют PKCE автоматически.

### Частые ошибки

| Ошибка | Причина | Исправление |
| --- | --- | --- |
| `invalid_client` | Неверные данные или клиент выключен | Проверьте ID, секрет и Enabled |
| `invalid_grant` | Код/токен истёк, использован или не совпал URI | Повторите вход и сравните URI |
| `invalid_scope` | Scope не разрешён | Измените Allowed scopes или запрос |
| `login_required` | Нет активной сессии | Откройте вход в браузере |
| `consent_required` | Нет согласия | Покажите consent или настройте Skip consent |
| `redirect_uri mismatch` | URI отличается | Сверьте адреса посимвольно |

## Проверки качества

Полный воспроизводимый набор серверных проверок запускается в Docker:

```bash
make quality
```

Команда собирает образ на Go 1.26.10 с закреплёнными версиями `govulncheck` и `golangci-lint`, затем проверяет форматирование, выполняет `go vet`, unit-тесты, race-тесты с CGO, поиск известных уязвимостей и lint. Перед запуском всё равно форматируйте изменённые Go-файлы командой `gofmt -w` и проверяйте патч через `git diff --check`.

Интеграционные тесты находятся в `internal/integration`, используют build tag `integration` и требуют отдельную базу PostgreSQL:

```bash
SSO_TEST_DATABASE_URL='postgres://sso:sso@127.0.0.1:5432/sso_test?sslmode=disable' go test -tags=integration ./internal/integration/...
```

Набор проверяет административные CRUD-сценарии и полный цикл миграций `up → down → up` на изолированной базе. Для фронтенда выполните `cd web/admin`, затем `npm ci`, `npm test`, `npm audit --omit=dev` и `npm run build`. UI smoke-тесты проверяют критические страницы на русском языке и безопасное отображение ошибок API. CI запускает unit-, race- и интеграционные тесты сервера, `govulncheck`, `golangci-lint`, а также тесты, сборку и аудит production-зависимостей фронтенда.

## План разработки

Только незавершённые улучшения перечисляются в [PLAN.md](PLAN.md). Завершённые возможности документируются здесь.
