# ── Docker Engineering Rules ──────────────────────────────────────────────────
# Multi-stage: builder installs C deps + Python packages; runner is lean.
# Non-root appuser; no secrets in image; apt caches purged in every stage.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Layer-cache: copy deps manifest first, install, then copy source
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# ── Stage 2: runner ───────────────────────────────────────────────────────────
FROM python:3.13-slim AS runner

# Runtime-only native library + non-root user in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system appgroup \
    && adduser --system --no-create-home --ingroup appgroup appuser

# Copy the pre-built venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Layer-cache: source code last
COPY --chown=appuser:appgroup . .

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
