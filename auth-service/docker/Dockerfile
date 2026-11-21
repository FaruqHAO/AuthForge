# =============================================================================
# Auth Service — Production Dockerfile
# =============================================================================
# Multi-stage build for minimal production image.
# Uses Python 3.13-slim for small footprint with full functionality.
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install system dependencies for building Python packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY app/ ./app/
RUN pip install --no-cache-dir --prefix=/install .


# ── Stage 2: Production ──────────────────────────────────────────────────
FROM python:3.13-slim AS production

# Security: Don't run as root
RUN groupadd -r authuser && useradd -r -g authuser -d /app -s /sbin/nologin authuser

# Install runtime dependencies only
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
WORKDIR /app
COPY app/ ./app/
COPY migrations/ ./migrations/
COPY alembic.ini .
COPY scripts/ ./scripts/

# Set ownership
RUN chown -R authuser:authuser /app

# Switch to non-root user
USER authuser

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/live || exit 1

EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]


# ── Stage 3: Development ─────────────────────────────────────────────────
FROM python:3.13-slim AS development

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DEBUG=true

WORKDIR /app

# Install all dependencies including dev tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app/ ./app/
RUN pip install --no-cache-dir -e ".[dev]"

COPY . .

EXPOSE 8000

# Run with auto-reload for development
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
