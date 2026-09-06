# Auth Service

A production-ready, reusable authentication and authorization microservice built with Python, FastAPI, PostgreSQL, and Redis. Designed to serve Angular web apps, Flutter mobile apps, and other backend APIs as a centralized identity service.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
  - [Authentication Flow](#authentication-flow)
  - [Token Refresh Flow](#token-refresh-flow)
  - [Password Reset Flow](#password-reset-flow)
  - [Authorization Flow (RBAC)](#authorization-flow-rbac)
  - [Session Management Flow](#session-management-flow)
- [Security Architecture](#security-architecture)
- [API Reference](#api-reference)
- [Environment Variables](#environment-variables)
- [Setup & Installation](#setup--installation)
  - [Prerequisites](#prerequisites)
  - [Local Development Setup](#local-development-setup)
  - [Docker Setup](#docker-setup)
  - [Database Setup](#database-setup)
  - [Seeding Default Data](#seeding-default-data)
- [Running the Service](#running-the-service)
- [Running Tests](#running-tests)
- [Code Quality](#code-quality)
- [Deployment](#deployment)
  - [Production Checklist](#production-checklist)
  - [Docker Deployment](#docker-deployment)
  - [SSL/TLS Configuration](#ssltls-configuration)
  - [Reverse Proxy (Nginx)](#reverse-proxy-nginx)
- [Troubleshooting](#troubleshooting)
- [Development Guide](#development-guide)
  - [Adding New Endpoints](#adding-new-endpoints)
  - [Adding New Models](#adding-new-models)
  - [Database Migrations](#database-migrations)
- [License](#license)

---

## Overview

Auth Service is a standalone microservice that handles all authentication and authorization concerns for your applications. Instead of building auth into every app, you run this service once and all your frontends (Angular, Flutter, React) and backends connect to it.

**Why a standalone auth service?**
- Single source of truth for user identity
- Consistent security across all applications
- Easier to audit, update, and maintain
- Supports multiple client types (web, mobile, service-to-service)

**Key Design Decisions:**
- **JWT-based**: Stateless tokens for horizontal scaling
- **Refresh token rotation**: Detects stolen tokens
- **Permission-based RBAC**: Not role-name checks — fine-grained `resource.action` permissions
- **Dual auth**: Supports both `Authorization: Bearer` header and secure `HttpOnly` cookies
- **Argon2id**: OWASP-recommended memory-hard password hashing
- **Append-only audit log**: Compliance-ready security event tracking

---

## Features

### Authentication
- User registration with email verification
- Login with email and password
- Logout (single session or all sessions)
- JWT access tokens (15-minute lifetime)
- Refresh token rotation (7-day lifetime)
- Refresh token reuse detection (kills stolen tokens)
- Dual auth: Bearer tokens + HttpOnly cookies

### Password Security
- Argon2id hashing (OWASP-recommended)
- Password strength validation (length, complexity)
- Secure password reset via email token
- Password change requires current password
- All sessions invalidated after password change

### Authorization (RBAC)
- Role-based access control with fine-grained permissions
- Permission format: `resource.action` (e.g., `tickets.delete`)
- Reusable FastAPI dependencies: `require_role("ADMIN")`, `require_permission("users.delete")`
- Multiple roles per user, multiple permissions per role
- Default roles auto-assigned on registration

### Session Management
- Track active sessions (IP, user agent, device info)
- View all active sessions
- Revoke individual sessions
- Revoke all sessions at once

### Security
- Rate limiting (Redis-backed): login, registration, password reset
- Account lockout after 5 failed attempts (15-minute cooldown)
- Security headers (OWASP): X-Content-Type-Options, X-Frame-Options, HSTS
- Anti-timing attacks on login
- User enumeration prevention (generic responses)
- Never expose internal errors or stack traces

### Audit Logging
- Append-only audit trail for compliance
- Tracks: LOGIN_SUCCESS, LOGIN_FAILED, PASSWORD_CHANGED, ROLE_ASSIGNED, etc.
- Never logs: passwords, tokens, secrets
- JSONB metadata for structured event data

### Infrastructure
- Async Python (FastAPI + asyncpg + async Redis)
- PostgreSQL 16 with connection pooling
- Redis 7 for rate limiting and caching
- Alembic database migrations
- Docker multi-stage builds (production + development)
- Health checks: `/health`, `/health/live`, `/health/ready`
- Structured JSON logging (production) and colorized (development)
- Request ID correlation across services

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Language | Python | 3.13+ | Core runtime |
| Web Framework | FastAPI | 0.115+ | Async HTTP API |
| Database | PostgreSQL | 16 | Primary data store |
| Cache/Limiting | Redis | 7 | Rate limiting, counters |
| ORM | SQLAlchemy | 2.x | Async database access |
| Migrations | Alembic | 1.13+ | Database schema management |
| Validation | Pydantic | 2.x | Request/response validation |
| Password Hashing | argon2-cffi | 23.1+ | OWASP-recommended hashing |
| JWT | python-jose | 3.3+ | Token creation and validation |
| HTTP Client | httpx | 0.27+ | API testing |
| Testing | pytest | 8.0+ | Test framework |
| Linting | Ruff | 0.5+ | Fast Python linter |
| Type Checking | MyPy | 1.10+ | Static type analysis |
| Containerization | Docker | - | Container builds |
| Orchestration | Docker Compose | - | Multi-service setup |

---

## Architecture

### High-Level Diagram

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Angular   │     │   Flutter   │     │   Other     │
│   Web App   │     │   Mobile    │     │   Backend   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │   Bearer Token /  │   Bearer Token    │   Bearer Token
       │   HttpOnly Cookie │                   │
       ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────┐
│                   Auth Service (FastAPI)                 │
│                                                         │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐           │
│  │    API     │  │  Service  │  │Repository │           │
│  │  Routes   │→ │  Layer    │→ │  Layer    │           │
│  └───────────┘  └───────────┘  └───────────┘           │
│       ↑              ↑              ↑                    │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐           │
│  │Middleware │  │  Security │  │   Audit   │           │
│  │Rate Limit│  │  (JWT/    │  │   Log     │           │
│  │Headers   │  │  Argon2)  │  │           │           │
│  └───────────┘  └───────────┘  └───────────┘           │
└───────────┬─────────────────────────┬───────────────────┘
            │                         │
            ▼                         ▼
     ┌─────────────┐          ┌─────────────┐
     │ PostgreSQL  │          │    Redis    │
     │  (Users,    │          │ (Rate Limit,│
     │   Roles,    │          │  Counters,  │
     │   Sessions) │          │   Locks)    │
     └─────────────┘          └─────────────┘
```

### Layered Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      API Layer                           │
│  Routes (auth.py, users.py, roles.py, sessions.py)      │
│  Schemas (request/response validation)                   │
│  Dependencies (authentication, authorization)            │
├─────────────────────────────────────────────────────────┤
│                    Service Layer                         │
│  AuthService (business logic for auth operations)        │
│  AuditService (security event logging)                   │
├─────────────────────────────────────────────────────────┤
│                  Repository Layer                        │
│  UserRepository (data access for users)                  │
│  RoleRepository (data access for roles/permissions)      │
├─────────────────────────────────────────────────────────┤
│                   Model Layer                            │
│  SQLAlchemy ORM models (User, Role, Permission, etc.)    │
├─────────────────────────────────────────────────────────┤
│                    Core Layer                            │
│  Config, Database, Redis, Security, Logging, Exceptions  │
├─────────────────────────────────────────────────────────┤
│                  Middleware Layer                         │
│  Request ID, Security Headers, Rate Limiting             │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
auth-service/
│
├── app/                            # Application source code
│   ├── __init__.py                 # Package init, version
│   ├── main.py                     # FastAPI app factory, lifespan, middleware
│   │
│   ├── api/                        # API layer
│   │   ├── __init__.py
│   │   ├── schemas.py              # Response envelope schemas
│   │   ├── exception_handlers.py   # Centralized error handling
│   │   └── v1/                     # Versioned API (v1)
│   │       ├── __init__.py
│   │       ├── router.py           # V1 router aggregation
│   │       ├── auth.py             # Authentication endpoints
│   │       ├── users.py            # Admin user management
│   │       ├── roles.py            # Admin role management
│   │       ├── permissions.py      # Admin permission management
│   │       ├── sessions.py         # Session management
│   │       ├── deps.py             # Authorization dependencies
│   │       └── health.py           # Health check endpoints
│   │
│   ├── core/                       # Core infrastructure
│   │   ├── __init__.py
│   │   ├── config.py               # Pydantic Settings (env vars)
│   │   ├── database.py             # Async SQLAlchemy engine/sessions
│   │   ├── redis.py                # Async Redis connection
│   │   ├── security.py             # Argon2id, JWT, token utilities
│   │   ├── logging.py              # Structured logging setup
│   │   ├── exceptions.py           # Exception hierarchy
│   │   └── dependencies.py         # FastAPI dependency injection
│   │
│   ├── middleware/                  # HTTP middleware
│   │   ├── __init__.py
│   │   ├── request_id.py           # Correlation ID tracking
│   │   ├── security_headers.py     # OWASP security headers
│   │   └── rate_limit.py           # Redis-backed rate limiting
│   │
│   ├── models/                     # SQLAlchemy ORM models
│   │   ├── __init__.py             # Model exports
│   │   ├── user.py                 # User entity
│   │   ├── role.py                 # Role entity
│   │   ├── permission.py           # Permission entity
│   │   ├── association.py          # UserRole, RolePermission
│   │   ├── session.py              # Login session tracking
│   │   ├── refresh_token.py        # Refresh token with chain tracking
│   │   └── audit_log.py            # Security audit log
│   │
│   ├── schemas/                    # Pydantic schemas
│   │   ├── __init__.py
│   │   └── auth.py                 # Auth request/response schemas
│   │
│   ├── repositories/               # Data access layer
│   │   ├── __init__.py
│   │   ├── user_repository.py      # User CRUD operations
│   │   └── role_repository.py      # Role/Permission CRUD
│   │
│   ├── services/                   # Business logic layer
│   │   ├── __init__.py
│   │   ├── auth_service.py         # Authentication operations
│   │   └── audit_service.py        # Audit logging service
│   │
│   └── utils/                      # Utility functions
│       └── __init__.py
│
├── migrations/                     # Alembic database migrations
│   ├── env.py                      # Migration environment config
│   ├── script.py.mako              # Migration script template
│   └── versions/
│       └── 001_initial_models.py   # Initial schema migration
│
├── tests/                          # Test suite
│   ├── __init__.py
│   ├── conftest.py                 # Shared fixtures
│   ├── unit/                       # Unit tests
│   │   ├── test_config.py          # Settings tests
│   │   ├── test_security.py        # Password/JWT tests
│   │   ├── test_auth_schemas.py    # Schema validation tests
│   │   ├── test_auth_service.py    # Business logic tests
│   │   ├── test_exceptions.py      # Exception hierarchy tests
│   │   ├── test_health.py          # Health endpoint tests
│   │   ├── test_middleware.py       # Middleware tests
│   │   ├── test_rate_limit.py      # Rate limiting tests
│   │   └── test_audit.py           # Audit logging tests
│   └── integration/                # Integration tests
│       └── test_auth_api.py        # API endpoint tests
│
├── scripts/                        # Utility scripts
│   └── seed_roles_permissions.py   # Seed default roles/permissions
│
├── docker/                         # Docker configuration
│   └── Dockerfile                  # Multi-stage build
│
├── docker-compose.yml              # PostgreSQL + Redis + API
├── alembic.ini                     # Alembic configuration
├── pyproject.toml                  # Project metadata & dependencies
├── .env.example                    # Environment variables template
├── .gitignore                      # Git ignore rules
├── .dockerignore                   # Docker build exclusions
├── .ruff.toml                      # Ruff linter configuration
└── README.md                       # This file
```

---

## How It Works

### Authentication Flow

```
1. Register
   Client → POST /api/v1/auth/register
   Server → Validate email uniqueness, password strength
   Server → Hash password (Argon2id)
   Server → Create user, assign default roles
   Server → Return user profile

2. Login
   Client → POST /api/v1/auth/login
   Server → Find user by email
   Server → Check account lock status
   Server → Verify password (Argon2id)
   Server → Create session + token family
   Server → Create refresh token (SHA-256 hashed for storage)
   Server → Create access token (JWT, 15 min)
   Server → Return { access_token, refresh_token, user }

3. Access Protected Resource
   Client → GET /api/v1/auth/me
   Header: Authorization: Bearer <access_token>
   Server → Decode JWT, verify signature + expiry
   Server → Extract user_id from "sub" claim
   Server → Return user profile

4. Logout
   Client → POST /api/v1/auth/logout
   Header: Authorization: Bearer <access_token>
   Server → Revoke session
   Server → Revoke all refresh tokens in session
```

### Token Refresh Flow

```
1. Access token expires (15 min)
2. Client sends refresh token:
   POST /api/v1/auth/refresh
   { "refresh_token": "..." }

3. Server validates refresh token:
   a. Decode JWT → verify signature + expiry
   b. Hash token → look up in database
   c. Check if revoked → if yes, TOKEN THEFT DETECTED
   d. Revoke old token (mark as rotated)
   e. Create new refresh token (same family, parent = old token)
   f. Create new access token

4. If revoked token reused:
   Server → Kill entire token family
   Server → Return 401 "Token reuse detected"
   Client → Must re-authenticate from scratch

5. Normal rotation:
   Server → Return { new_access_token, new_refresh_token }
   Client → Store new tokens, discard old ones
```

### Password Reset Flow

```
1. Request reset:
   POST /api/v1/auth/forgot-password
   { "email": "user@example.com" }

   Server → Always returns success (prevents user enumeration)
   Server → If email exists: generate reset token, send email
   Server → If email doesn't exist: do nothing

2. Reset password:
   POST /api/v1/auth/reset-password
   { "token": "...", "new_password": "..." }

   Server → Validate reset token (single-use, 15-min expiry)
   Server → Update password hash
   Server → Invalidate all sessions (security measure)
   Server → Return success
```

### Authorization Flow (RBAC)

```
Permission-based authorization (NOT role-name checks):

1. Assign roles to users:
   POST /api/v1/admin/users/{id}/roles
   { "role_id": "..." }

2. Assign permissions to roles:
   POST /api/v1/admin/roles/{id}/permissions
   { "permission_id": "..." }

3. Protect endpoints with permissions:
   @router.delete("/tickets/{id}")
   async def delete_ticket(
       payload = Depends(require_permission("tickets.delete"))
   ):
       # Only users with "tickets.delete" permission can access
       ...

4. Protect endpoints with roles:
   @router.get("/admin/users")
   async def list_users(
       payload = Depends(require_role("ADMIN"))
   ):
       # Only users with "ADMIN" role can access
       ...

5. Check authenticated user:
   @router.get("/profile")
   async def get_profile(
       payload = Depends(require_authenticated_user)
   ):
       # Any logged-in user can access
       ...
```

### Session Management Flow

```
1. List sessions:
   GET /api/v1/auth/sessions
   → Returns all active sessions with IP, user agent, timestamps

2. Revoke specific session:
   DELETE /api/v1/auth/sessions/{session_id}
   → Revokes session + all its refresh tokens

3. Revoke all sessions:
   DELETE /api/v1/auth/sessions
   → Logs out from everywhere (useful after password change)
```

---

## Security Architecture

### Password Storage

```
Password → Argon2id hash → Database
                ↓
        $argon2id$v=19$m=65536,t=3,p=4$...
        (includes random salt, never stored separately)
```

**Argon2id parameters:**
- Time cost: 3 iterations
- Memory cost: 64 MB
- Parallelism: 4 threads
- Hash length: 32 bytes
- Salt length: 16 bytes (random per password)

### JWT Token Structure

```json
{
  "sub": "user-uuid",
  "jti": "unique-token-id",
  "iss": "auth-service",
  "aud": "auth-service",
  "iat": 1694000000,
  "exp": 1694000900,
  "type": "access",
  "roles": ["ADMIN", "USER"],
  "permissions": ["users.read", "tickets.delete"]
}
```

### Refresh Token Security

```
Raw token (sent to client):
  → secrets.token_urlsafe(64) — 86-char URL-safe string

Hashed token (stored in DB):
  → SHA-256(raw_token) — 64-char hex digest

Chain tracking:
  Token A → Token B → Token C (current)
  parent_id links each token to its predecessor

Family tracking:
  All tokens from one login share family_id
  If any revoked token is reused → kill entire family
```

### Rate Limiting

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| POST /auth/login | 5 attempts | 1 minute | Per IP |
| POST /auth/register | 3 attempts | 1 hour | Per IP |
| POST /auth/forgot-password | 3 attempts | 1 hour | Per IP |

### Account Lockout

| Threshold | Duration | Reset |
|-----------|----------|-------|
| 5 failed login attempts | 15 minutes | Successful login |

### Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Strict-Transport-Security: max-age=31536000; includeSubDomains (production)
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Cookie vs Bearer Token

| Aspect | Bearer Token | HttpOnly Cookie |
|--------|-------------|-----------------|
| Storage | Client-side (memory) | Browser cookie |
| XSS Risk | Higher (localStorage) | Lower (HttpOnly) |
| CSRF Risk | Lower | Higher (SameSite helps) |
| Mobile Support | Yes | Limited |
| Cross-origin | Yes | Depends on SameSite |
| Recommended For | Flutter, service-to-service | Angular, React |

**To enable cookie auth:** Set `COOKIE_ENABLED=true` in `.env`

---

## API Reference

### Authentication Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/register` | No | Register new user |
| POST | `/api/v1/auth/login` | No | Login and get tokens |
| POST | `/api/v1/auth/logout` | Yes | Logout current session |
| POST | `/api/v1/auth/refresh` | No | Refresh access token |
| GET | `/api/v1/auth/me` | Yes | Get current user profile |
| PUT | `/api/v1/auth/me` | Yes | Update profile |
| POST | `/api/v1/auth/change-password` | Yes | Change password |
| POST | `/api/v1/auth/forgot-password` | No | Request password reset |
| POST | `/api/v1/auth/reset-password` | No | Reset password with token |
| POST | `/api/v1/auth/verify-email` | No | Verify email with token |
| POST | `/api/v1/auth/resend-verification` | No | Resend verification email |

### Session Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/auth/sessions` | Yes | List active sessions |
| DELETE | `/api/v1/auth/sessions/{id}` | Yes | Revoke specific session |
| DELETE | `/api/v1/auth/sessions` | Yes | Revoke all sessions |

### Admin Endpoints

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/admin/users` | ADMIN | List users (paginated) |
| GET | `/api/v1/admin/users/{id}` | ADMIN | Get user details |
| PUT | `/api/v1/admin/users/{id}` | ADMIN | Update user |
| DELETE | `/api/v1/admin/users/{id}` | ADMIN | Deactivate user |
| POST | `/api/v1/admin/users/{id}/activate` | ADMIN | Activate user |
| GET | `/api/v1/admin/roles` | ADMIN | List all roles |
| POST | `/api/v1/admin/roles` | ADMIN | Create role |
| PUT | `/api/v1/admin/roles/{id}` | ADMIN | Update role |
| DELETE | `/api/v1/admin/roles/{id}` | ADMIN | Delete role |
| POST | `/api/v1/admin/roles/{id}/permissions` | ADMIN | Assign permission |
| DELETE | `/api/v1/admin/roles/{id}/permissions/{pid}` | ADMIN | Remove permission |
| GET | `/api/v1/admin/permissions` | ADMIN | List all permissions |
| POST | `/api/v1/admin/permissions` | ADMIN | Create permission |

### Health Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Full health check (DB + Redis) |
| GET | `/health/live` | Liveness probe (always 200) |
| GET | `/health/ready` | Readiness probe (DB + Redis must be healthy) |

### Response Format

**Success:**
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation successful"
}
```

**Error:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Wrong email or password |
| `ACCOUNT_LOCKED` | 401 | Too many failed attempts |
| `ACCOUNT_DISABLED` | 401 | Account deactivated |
| `EMAIL_NOT_VERIFIED` | 401 | Email not verified |
| `TOKEN_EXPIRED` | 401 | Token has expired |
| `TOKEN_INVALID` | 401 | Token is malformed |
| `REFRESH_TOKEN_REVOKED` | 401 | Refresh token revoked |
| `REFRESH_TOKEN_REUSE_DETECTED` | 401 | Token theft detected |
| `PERMISSION_DENIED` | 403 | Missing specific permission |
| `INSUFFICIENT_PERMISSIONS` | 403 | Missing required role |
| `USER_NOT_FOUND` | 404 | User doesn't exist |
| `EMAIL_ALREADY_EXISTS` | 409 | Email already registered |
| `USERNAME_TAKEN` | 409 | Username already in use |
| `WEAK_PASSWORD` | 422 | Password too weak |
| `VALIDATION_ERROR` | 422 | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `DATABASE_ERROR` | 500 | Database operation failed |

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

### Application
| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `Auth Service` | Service display name |
| `APP_VERSION` | `0.1.0` | Service version |
| `ENVIRONMENT` | `development` | `development`, `testing`, `staging`, `production` |
| `DEBUG` | `true` | Enable debug mode (Swagger docs, auto-reload) |
| `SECRET_KEY` | - | **Required.** Application signing key (min 32 chars) |
| `ALLOWED_ORIGINS` | `http://localhost:4200` | CORS allowed origins (comma-separated) |

### Database
| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://auth_user:auth_password@localhost:5432/auth_db` | PostgreSQL connection string |
| `DATABASE_ECHO` | `false` | Log SQL statements |
| `DATABASE_POOL_SIZE` | `5` | Connection pool size |
| `DATABASE_MAX_OVERFLOW` | `10` | Max overflow connections |

### Redis
| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |

### JWT
| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | - | **Required.** JWT signing key (min 32 chars, different from SECRET_KEY) |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `JWT_ISSUER` | `auth-service` | JWT issuer claim |
| `JWT_AUDIENCE` | `auth-service` | JWT audience claim |

### SMTP (Email)
| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `localhost` | SMTP server host |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | - | SMTP username |
| `SMTP_PASSWORD` | - | SMTP password |
| `SMTP_FROM_ADDRESS` | `noreply@auth-service.local` | Sender email address |
| `SMTP_USE_TLS` | `true` | Use TLS encryption |

### Rate Limiting
| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_LOGIN` | `5/minute` | Max login attempts per window |
| `RATE_LIMIT_REGISTER` | `3/hour` | Max registration attempts per window |
| `RATE_LIMIT_PASSWORD_RESET` | `3/hour` | Max password reset requests per window |

### Cookie Auth
| Variable | Default | Description |
|----------|---------|-------------|
| `COOKIE_ENABLED` | `false` | Enable cookie-based authentication |
| `COOKIE_DOMAIN` | `localhost` | Cookie domain |
| `COOKIE_SECURE` | `false` | Set Secure flag (must be `true` in production) |
| `COOKIE_SAMESITE` | `strict` | SameSite policy: `strict`, `lax`, or `none` |

### Admin Bootstrap
| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_EMAIL` | `admin@example.com` | Initial admin email (for seed script) |
| `ADMIN_PASSWORD` | - | Initial admin password (for seed script only) |

---

## Setup & Installation

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.13+ | Runtime |
| pip | Latest | Package installer |
| Docker | 24+ | Container runtime |
| Docker Compose | 2.20+ | Multi-container orchestration |
| Git | 2.40+ | Version control |

### Local Development Setup

**Step 1: Clone the repository**
```bash
git clone <repository-url>
cd auth-service
```

**Step 2: Create a virtual environment**
```bash
python -m venv .venv

# Activate it:
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows (PowerShell)
.venv\Scripts\activate.bat       # Windows (cmd)
```

**Step 3: Install dependencies**
```bash
pip install -e ".[dev]"
```

This installs:
- FastAPI, SQLAlchemy, Pydantic (runtime)
- pytest, Ruff, MyPy (development)
- All transitive dependencies

**Step 4: Configure environment**
```bash
cp .env.example .env
```

**Step 5: Generate secure keys**
```bash
# Generate two different 64-character hex keys
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
```

Copy the output into your `.env` file, replacing the placeholder values.

**Step 6: Start PostgreSQL and Redis**
```bash
docker compose up -d postgres redis
```

Wait for them to be healthy:
```bash
docker compose ps
# postgres should show "healthy"
# redis should show "healthy"
```

**Step 7: Run database migrations**
```bash
alembic upgrade head
```

This creates all 8 tables:
- `users` — User accounts
- `roles` — RBAC roles
- `permissions` — Fine-grained permissions
- `user_roles` — User-to-role assignments
- `role_permissions` — Role-to-permission grants
- `sessions` — Login session tracking
- `refresh_tokens` — Refresh tokens with chain tracking
- `audit_logs` — Security audit trail

**Step 8: Seed default data**
```bash
ADMIN_PASSWORD=YourSecurePass1! ADMIN_EMAIL=admin@example.com \
  python -m scripts.seed_roles_permissions
```

This creates:
- **4 roles**: ADMIN, MANAGER, SUPPORT, USER
- **10 permissions**: users.{read,create,update,delete}, tickets.{read,create,update,delete}, reports.read, system.manage
- **Role-permission mappings**: ADMIN gets all, MANAGER gets most, SUPPORT gets limited, USER gets basic
- **1 admin user**: `admin@example.com` with the password you specified

**Step 9: Start the development server**
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Step 10: Verify**
```bash
# Health check
curl http://localhost:8000/health

# API documentation (only in debug mode)
# Open http://localhost:8000/docs in your browser

# Test registration
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"StrongPass123!"}'

# Test login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"YourSecurePass1!"}'
```

### Docker Setup

**Everything in Docker (simplest):**
```bash
# Start all services (PostgreSQL + Redis + API)
docker compose up -d

# Run migrations inside the API container
docker compose exec api alembic upgrade head

# Seed default data
docker compose exec api \
  env ADMIN_PASSWORD=YourSecurePass1! \
      ADMIN_EMAIL=admin@example.com \
  python -m scripts.seed_roles_permissions

# View logs
docker compose logs -f api

# Stop everything
docker compose down
```

**Development with hot-reload:**
```bash
# Build the development image
docker compose build api --target development

# Start with volume mounts for live code changes
docker compose up api
```

**Production build:**
```bash
# Build the production image
docker compose build api --target production

# Start production services
docker compose up -d
```

### Database Setup

**Connecting directly:**
```bash
# Connect to PostgreSQL
psql -h localhost -U auth_user -d auth_db
# Password: auth_password (from docker-compose.yml)

# Useful queries
\dt                          # List tables
SELECT count(*) FROM users;  # Count users
SELECT * FROM roles;         # List roles
```

**Running migrations:**
```bash
# Apply all pending migrations
alembic upgrade head

# Check current migration version
alembic current

# View migration history
alembic history

# Rollback one step
alembic downgrade -1

# Rollback to specific version
alembic downgrade <revision_id>
```

**Creating a new migration:**
```bash
# Auto-generate from model changes
alembic revision --autogenerate -m "add new field to users"

# Create empty migration (manual)
alembic revision -m "custom migration"
```

### Seeding Default Data

The seed script is idempotent — safe to run multiple times:

```bash
# Basic seeding
python -m scripts.seed_roles_permissions

# With specific admin credentials
ADMIN_PASSWORD=MySecurePass1! \
ADMIN_EMAIL=admin@mycompany.com \
  python -m scripts.seed_roles_permissions
```

**What gets seeded:**

| Entity | Count | Details |
|--------|-------|---------|
| Permissions | 10 | users.{read,create,update,delete}, tickets.{read,create,update,delete}, reports.read, system.manage |
| Roles | 4 | ADMIN (all perms), MANAGER (most), SUPPORT (limited), USER (basic) |
| Admin User | 1 | Pre-verified, assigned ADMIN role |

---

## Running the Service

### Development Mode
```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Start the API with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# The server auto-reloads when you change code
# Swagger docs available at http://localhost:8000/docs
```

### Production Mode
```bash
# Start all services
docker compose up -d

# Or run with uvicorn directly (4 workers)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Verify the Service
```bash
# Full health check (checks DB + Redis)
curl http://localhost:8000/health
# → {"status":"healthy","services":{"database":"healthy","redis":"healthy"}}

# Liveness probe (always 200 if process running)
curl http://localhost:8000/health/live
# → {"status":"alive"}

# Readiness probe (200 if can serve traffic)
curl http://localhost:8000/health/ready
# → {"status":"ready"}

# API documentation
open http://localhost:8000/docs
```

---

## Running Tests

### Run All Tests
```bash
pytest
```

### Run with Coverage
```bash
pytest --cov=app --cov-report=html --cov-report=term
# Open htmlcov/index.html for detailed coverage report
```

### Run Specific Test Categories
```bash
# Unit tests only (no external dependencies)
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v

# Specific test file
pytest tests/unit/test_security.py -v

# Specific test class
pytest tests/unit/test_security.py::TestPasswordHashing -v

# Specific test function
pytest tests/unit/test_security.py::TestPasswordHashing::test_hash_password_returns_string -v
```

### Run Tests Matching a Pattern
```bash
# Tests with "login" in the name
pytest -k login -v

# Tests with "password" in the name
pytest -k password -v

# Exclude slow tests
pytest -m "not slow" -v
```

---

## Code Quality

### Linting with Ruff
```bash
# Check for lint errors
ruff check app/

# Auto-fix lint errors
ruff check app/ --fix

# Format code
ruff format app/

# Check formatting without changing files
ruff format --check app/
```

### Type Checking with MyPy
```bash
# Run type checker
mypy app/

# Strict mode (enabled in pyproject.toml)
mypy app/ --strict
```

### Run All Quality Checks
```bash
ruff check app/ && ruff format --check app/ && mypy app/ && pytest
```

---

## Deployment

### Production Checklist

Before deploying to production:

- [ ] **Environment**: Set `ENVIRONMENT=production`
- [ ] **Secrets**: Generate strong `SECRET_KEY` and `JWT_SECRET_KEY` (min 32 chars each, different values)
- [ ] **Database**: Configure `DATABASE_URL` with production PostgreSQL credentials
- [ ] **Redis**: Configure `REDIS_URL` with production Redis
- [ ] **CORS**: Set `ALLOWED_ORIGINS` to your actual domain(s)
- [ ] **Cookies**: Set `COOKIE_SECURE=true` for HTTPS
- [ ] **Debug**: Set `DEBUG=false` (disables Swagger docs)
- [ ] **SSL/TLS**: Configure HTTPS at reverse proxy (nginx/traefik)
- [ ] **Logging**: Set up log aggregation (ELK, Datadog, CloudWatch)
- [ ] **Monitoring**: Configure health check monitoring and alerting
- [ ] **Database**: Run `alembic upgrade head`
- [ ] **Seed**: Run seed script with production admin password
- [ ] **Verify**: Confirm `/health` returns 200
- [ ] **SMTP**: Configure email sending for verification and password reset

### Docker Deployment

```bash
# Build production image
docker compose build api --target production

# Start all services
docker compose up -d

# Verify
docker compose ps
curl http://localhost:8000/health

# View logs
docker compose logs -f api
```

### SSL/TLS Configuration

Always use HTTPS in production. Configure SSL termination at your reverse proxy:

**Nginx:**
```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/ssl/certs/auth.example.com.pem;
    ssl_certificate_key /etc/ssl/private/auth.example.com.key;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://auth-service:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$server_name$request_uri;
}
```

**Traefik (Docker labels):**
```yaml
api:
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.auth.rule=Host(`auth.example.com`)"
    - "traefik.http.routers.auth.entrypoints=websecure"
    - "traefik.http.routers.auth.tls.certresolver=letsencrypt"
    - "traefik.http.services.auth.loadbalancer.server.port=8000"
```

### Reverse Proxy (Nginx)

Full Nginx configuration for production:

```nginx
upstream auth_service {
    server auth-service:8000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/ssl/certs/auth.example.com.pem;
    ssl_certificate_key /etc/ssl/private/auth.example.com.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # Proxy settings
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Connection "";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;

    location /api/v1/auth/login {
        limit_req zone=auth burst=20 nodelay;
        proxy_pass http://auth_service;
    }

    location /api/v1/auth/register {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://auth_service;
    }

    location / {
        proxy_pass http://auth_service;
    }
}
```

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `alembic upgrade head` fails | PostgreSQL not running | `docker compose up -d postgres` and wait for healthy |
| `Redis client not initialized` | Redis not running | `docker compose up -d redis` |
| `ModuleNotFoundError: app` | Not installed in dev mode | `pip install -e ".[dev]"` from `auth-service/` |
| `JWT_SECRET_KEY` validation error | Key too short | Use at least 32 characters |
| Port 5432 already in use | Local PostgreSQL running | Stop it or change port in `docker-compose.yml` |
| `Connection refused` on localhost | Docker services not started | `docker compose up -d` |
| `Permission denied` on .env | File permissions | `chmod 600 .env` |
| Tests fail with import errors | Virtual environment not activated | `source .venv/bin/activate` |
| `KeyError: 'DATABASE_URL'` | Missing env var | Copy `.env.example` to `.env` and configure |
| Rate limiting not working | Redis not connected | Check Redis is running and `REDIS_URL` is correct |

### Checking Service Status

```bash
# Check all containers
docker compose ps

# Check PostgreSQL
docker compose exec postgres pg_isready -U auth_user

# Check Redis
docker compose exec redis redis-cli ping

# Check API logs
docker compose logs api --tail 50

# Check database connection
docker compose exec api python -c "
from sqlalchemy import text
from app.core.database import init_db, get_session_factory
import asyncio

async def check():
    await init_db()
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(text('SELECT 1'))
        print('Database connected:', result.scalar())

asyncio.run(check())
"
```

---

## Development Guide

### Adding New Endpoints

1. Create or update the route file in `app/api/v1/`:
```python
# app/api/v1/my_feature.py
from fastapi import APIRouter, Depends
from app.api.v1.deps import require_permission

router = APIRouter()

@router.get("/my-endpoint")
async def my_endpoint(
    payload = Depends(require_permission("my.permission")),
):
    return {"message": "Hello"}
```

2. Register the router in `app/api/v1/router.py`:
```python
from app.api.v1.my_feature import router as my_feature_router
api_v1_router.include_router(my_feature_router, prefix="/my-feature", tags=["My Feature"])
```

### Adding New Models

1. Create the model in `app/models/`:
```python
# app/models/my_model.py
from sqlalchemy import Column, String
from app.core.database import Base

class MyModel(Base):
    __tablename__ = "my_models"
    id = Column(String, primary_key=True)
    name = Column(String(100), nullable=False)
```

2. Import it in `app/models/__init__.py`:
```python
from app.models.my_model import MyModel
```

3. Generate a migration:
```bash
alembic revision --autogenerate -m "add my_model"
alembic upgrade head
```

### Database Migrations

```bash
# Create migration from model changes
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1

# Check current version
alembic current

# View history
alembic history --verbose
```

---

## License

MIT
