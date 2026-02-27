# ── Docker Engineering Rules ──────────────────────────────────────────────────
# Three-stage build:
#   wasm-builder — Rust toolchain compiles the Wasm module
#   deps         — Node.js installs npm packages (layer-cached separately)
#   runner       — Minimal Alpine image; non-root appuser
# No secrets in image; all caches purged.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Rust/Wasm builder ────────────────────────────────────────────────
FROM rust:1.75-slim AS wasm-builder
WORKDIR /wasm_build

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
COPY ./wasm ./wasm
RUN cd wasm && wasm-pack build --target web --out-dir ../pkg

# ── Stage 2: Node.js dependency installer ─────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app

# Layer-cache: copy manifests first, install, then source
COPY frontend/package*.json ./
RUN npm ci \
    && rm -rf /root/.npm

# ── Stage 3: runner ───────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

# Non-root user (Alpine syntax)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy pre-installed node_modules from deps stage
COPY --from=deps    --chown=appuser:appgroup /app/node_modules    ./node_modules

# Copy compiled Wasm artefacts from wasm-builder stage
COPY --from=wasm-builder --chown=appuser:appgroup /wasm_build/pkg ./wasm/pkg

# Layer-cache: source code last
COPY --chown=appuser:appgroup frontend/ .

USER appuser
EXPOSE 3000
CMD ["npm", "run", "dev"]
