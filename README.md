# PayFlow — auth-service

Owns user accounts, authentication and JWT issuance for the PayFlow wallet platform.
One of five independent services; the other four verify this service's access tokens
using the shared signing key, without calling back here.

- **Java 21**, **Spring Boot 4.1.0** (Spring Framework 7, Spring Security 7, Hibernate 7)
- **PostgreSQL**, schema owned by **Flyway** (Hibernate runs in `validate` mode)
- **Port 8081**

---

## Running it

### 1. Start a database

```bash
docker run -d --name payflow-auth-db \
  -e POSTGRES_DB=payflow_auth \
  -e POSTGRES_USER=payflow \
  -e POSTGRES_PASSWORD=payflow \
  -p 5432:5432 postgres:16-alpine
```

### 2. Run the service

```bash
./mvnw spring-boot:run
```

The `dev` profile is active by default and every setting falls back to a working local
value, so no environment variables are needed to start. Flyway applies
`V1__create_users_and_refresh_tokens.sql` on first boot.

- API: <http://localhost:8081/api/v1/auth>
- Swagger UI: <http://localhost:8081/swagger-ui.html>
- OpenAPI JSON: <http://localhost:8081/v3/api-docs>
- Health: <http://localhost:8081/actuator/health>

### 3. Tests

```bash
./mvnw test
```

53 tests. The integration test starts a real PostgreSQL container, so **Docker must be
running**.

### 4. Docker

```bash
docker build -t payflow/auth-service:latest .

docker run --rm -p 8081:8081 \
  -e DB_URL=jdbc:postgresql://host.docker.internal:5432/payflow_auth \
  -e DB_USERNAME=payflow \
  -e DB_PASSWORD=payflow \
  -e JWT_SECRET="$(openssl rand -base64 48)" \
  payflow/auth-service:latest
```

The image defaults to `SPRING_PROFILES_ACTIVE=prod`, which has **no fallbacks** — the
four variables above are required or the container exits at startup.

---

## Environment variables

| Variable | Required | Dev default | Purpose |
|---|---|---|---|
| `DB_URL` | prod only | `jdbc:postgresql://localhost:5432/payflow_auth` | JDBC URL |
| `DB_USERNAME` | prod only | `payflow` | Database user |
| `DB_PASSWORD` | prod only | `payflow` | Database password |
| `JWT_SECRET` | **prod only** | `dev-secret-change-me-…` | HMAC signing key, **min 32 bytes** |
| `JWT_ISSUER` | no | `payflow-auth-service` | `iss` claim; verified on every parse |
| `JWT_ACCESS_TTL` | no | `15m` | Access token lifetime |
| `JWT_REFRESH_TTL` | no | `7d` | Refresh token lifetime |
| `SERVER_PORT` | no | `8081` | HTTP port |
| `SPRING_PROFILES_ACTIVE` | no | `dev` | `dev` or `prod` |
| `DB_POOL_MAX` / `DB_POOL_MIN` | no | `10` / `2` | Hikari pool size |
| `LOG_LEVEL` | no | `DEBUG` (dev) | Level for `com.payflow.auth` |
| `SWAGGER_UI_ENABLED` | no | `false` (prod) | Swagger UI in production |

A secret shorter than 32 bytes is rejected at startup rather than at first login.

---

## Endpoints

Base path `/api/v1/auth`. **Public:** `register`, `login`, `refresh`.
**Authenticated:** `logout`, `me`.

| Method | Path | Auth | Success | Errors |
|---|---|---|---|---|
| `POST` | `/register` | — | `201` `UserResponse` | `400`, `409` |
| `POST` | `/login` | — | `200` `AuthResponse` | `400`, `401` |
| `POST` | `/refresh` | — | `200` `AuthResponse` | `400`, `401` |
| `POST` | `/logout` | Bearer | `204` | `401` |
| `GET` | `/me` | Bearer | `200` `UserResponse` | `401` |

### Register

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "ada@payflow.io",
    "password": "correct-horse-9",
    "fullName": "Ada Lovelace",
    "phoneNumber": "+441632960961"
  }'
```

```json
{
  "id": "112ff3c3-29b4-4704-aa05-53ff9b155534",
  "email": "ada@payflow.io",
  "fullName": "Ada Lovelace",
  "phoneNumber": "+441632960961",
  "role": "USER",
  "enabled": true,
  "createdAt": "2026-08-10T15:02:36.149405Z"
}
```

Emails are stored lower-cased, so `Ada@PayFlow.io` and `ada@payflow.io` are one account.
Password must be 8–72 characters with at least one letter and one digit.

### Login

```bash
curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@payflow.io","password":"correct-horse-9"}'
```

```json
{
  "accessToken": "eyJhbGciOiJIUzM4NCJ9...",
  "refreshToken": "eyJhbGciOiJIUzM4NCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "user": { "id": "112ff3c3-...", "email": "ada@payflow.io", "role": "USER" }
}
```

`expiresIn` is seconds, so clients can refresh ahead of expiry instead of waiting for a 401.

### Current profile

```bash
ACCESS=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@payflow.io","password":"correct-horse-9"}' | jq -r .accessToken)

curl -s http://localhost:8081/api/v1/auth/me -H "Authorization: Bearer $ACCESS"
```

### Refresh

```bash
curl -s -X POST http://localhost:8081/api/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refresh token>"}'
```

Returns a full `AuthResponse`. **The refresh token is rotated**: the presented one is
revoked and a new one issued, so each refresh token works exactly once. Store the new
value.

### Logout

```bash
curl -i -X POST http://localhost:8081/api/v1/auth/logout \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refresh token>"}'
```

`204`. Idempotent — an unknown, already-revoked or someone else's token also returns
`204`, so the endpoint cannot be used to probe which tokens exist.

---

## Errors

Every failure — including ones raised inside the security filter chain — uses one shape:

```json
{
  "timestamp": "2026-08-10T15:02:36.241504001Z",
  "status": 409,
  "error": "Conflict",
  "message": "An account already exists for ada@payflow.io",
  "path": "/api/v1/auth/register"
}
```

`validationErrors` is added only for `400`s from bean validation, and lists every
rejected field at once:

```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "Request validation failed",
  "path": "/api/v1/auth/register",
  "validationErrors": {
    "email": "Email must be a well-formed address",
    "password": "Password must be between 8 and 72 characters"
  }
}
```

| Status | When |
|---|---|
| `400` | Bean validation failed, or the body could not be parsed |
| `401` | Bad credentials, or a missing/expired/invalid token |
| `403` | Authenticated but not permitted |
| `404` | Record does not exist |
| `409` | Email already registered |
| `500` | Unexpected — stack trace goes to the log, never to the caller |

---

## Design notes

### Why refresh tokens are stored when JWTs are stateless

The **access token** is self-contained by design: wallet, payments, ledger and
notifications verify it with the signing key alone, no round trip to this service. That
independence is what makes the platform scale — and it means an access token **cannot be
revoked**, only expired. Hence the 15-minute lifetime.

The **refresh token** has the opposite requirement. Logout, a password change or a stolen
device must end a session immediately, which is impossible without server-side state. So
refresh tokens get a row in `refresh_tokens` with a `revoked` flag that is checked on
every use.

Fast stateless verification on the hot path, real revocation on the cold path. The
15-minute access TTL is exactly the width of the window in which revocation is imperfect.

### Access and refresh tokens are not interchangeable

Both are JWTs signed with the same key, so structurally a refresh token would pass as a
bearer credential. A `type` claim (`access` / `refresh`) is enforced on every
authenticated request, which is what stops a stolen 7-day refresh token being replayed
against the rest of the platform. Tokens also carry a random `jti`, so two issued in the
same second are distinct.

### Filter chain

`JwtAuthenticationFilter` (a `OncePerRequestFilter`) runs **before**
`UsernamePasswordAuthenticationFilter`, so the `SecurityContext` is populated before the
authorization rules are evaluated. A missing or invalid token is deliberately *not* an
error there — the filter leaves the context empty and continues, and the authorization
rules decide. That is why the same filter can sit in front of `/login` without
special-casing public paths.

Authentication and authorization failures happen inside the chain, before any controller
is selected, so `@RestControllerAdvice` never sees them. `JwtAuthenticationEntryPoint`
and `RestAccessDeniedHandler` produce the same `ErrorResponse` body for those.

### CSRF is disabled

CSRF protection defends against a browser silently attaching **ambient credentials** (a
session cookie) to a forged cross-site request. This service issues no cookies and keeps
no session; the only credential is a bearer token that JavaScript must read from storage
and set on an `Authorization` header, which a cross-site form post cannot do. With no
ambient credential to abuse, a CSRF token would guard nothing.

### Account enumeration

A wrong password, an unregistered email and a disabled account all return the same `401`
`"Invalid email or password"`. Spring checks account status *before* verifying the
password, so a distinct "account disabled" reply would confirm an address is registered
to anyone who typed a wrong password against it.

> If you would rather tell disabled users why they cannot log in, split
> `handleAuthentication` in `GlobalExceptionHandler` to treat `DisabledException`
> separately. That is a deliberate trade of enumeration resistance for clearer UX.

---

## Layout

```
com.payflow.auth
├── config/       JwtProperties, SecurityConfig, OpenApiConfig
├── controller/   AuthController
├── service/      AuthService
├── repository/   UserRepository, RefreshTokenRepository
├── entity/       User, RefreshToken, Role
├── dto/
│   ├── request/  RegisterRequest, LoginRequest, RefreshTokenRequest
│   └── response/ UserResponse, AuthResponse, ErrorResponse
├── mapper/       UserMapper
├── security/     JwtService, JwtAuthenticationFilter, UserPrincipal,
│                 CustomUserDetailsService, JwtAuthenticationEntryPoint,
│                 RestAccessDeniedHandler
└── exception/    GlobalExceptionHandler + ResourceNotFound / Duplicate / InvalidToken
```

Conventions: constructor injection only, entities never leave the service layer as
responses, business logic stays out of controllers, `@Transactional` on writing service
methods.

### Schema

`users` — `id` (UUID PK), `email` (unique, indexed), `password_hash`, `full_name`,
`phone_number`, `enabled`, `role` (`CHECK IN ('USER','ADMIN')`), `created_at`,
`updated_at`.

`refresh_tokens` — `id` (UUID PK), `token` (unique), `user_id`
(FK → `users` `ON DELETE CASCADE`, indexed), `expiry_date` (indexed), `revoked`,
`created_at`.

Schema changes go in a new `V2__*.sql`; Hibernate never writes DDL.
