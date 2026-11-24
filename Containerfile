FROM docker.io/library/node:24-alpine AS frontend-builder

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
ARG VITE_AUTHENTIK_AUTHORIZE_URL=http://localhost:9000/application/o/authorize/
ARG VITE_AUTHENTIK_CLIENT_ID=locker-client-id
ARG VITE_AUTHENTIK_ADMIN_URL=
ARG VITE_OIDC_REDIRECT_URI=
ENV VITE_AUTHENTIK_AUTHORIZE_URL=${VITE_AUTHENTIK_AUTHORIZE_URL} \
    VITE_AUTHENTIK_CLIENT_ID=${VITE_AUTHENTIK_CLIENT_ID} \
    VITE_AUTHENTIK_ADMIN_URL=${VITE_AUTHENTIK_ADMIN_URL} \
    VITE_OIDC_REDIRECT_URI=${VITE_OIDC_REDIRECT_URI}
RUN npm run build && \
    find /frontend/dist -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' -o -name '*.json' \) -size +256c \
      -exec sh -c 'for f; do gzip -9 -c "$f" > "$f.gz"; done' _ {} +

FROM docker.io/library/rust:1-slim-bookworm AS backend-builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --release --locked

FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /certs /app/static
COPY --from=backend-builder /app/target/release/locker-backend /usr/local/bin/locker-backend
COPY --from=frontend-builder /frontend/dist /app/static

EXPOSE 8080
ENV HTTP_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/locker.db?mode=rwc \
    STATIC_DIR=/app/static

HEALTHCHECK --interval=10s --timeout=5s --retries=10 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["/usr/local/bin/locker-backend"]
