# Arkfile Production Container Deployment (Podman)

## 1. Philosophy

This deployment strategy targets **production self-hosted environments** with maximum security and minimal footprint:

1. **Minimal Images:** Application containers use Alpine-based multi-stage builds. The rqlite container uses `FROM scratch` (pure Go, no CGO). No full distros, no shell access in final images where possible.
2. **Rootless (Podman):** All containers run as a non-root user on the host. Even if a container is compromised, the attacker gains no privileges on the host system.
3. **Daemonless:** Podman requires no central root daemon — containers are child processes of your user session.
4. **Separation of Concerns:** Each component (App, DB, Proxy, Storage) runs in its own isolated container with network segmentation.

## 2. Why Podman over Docker?

- **Rootless by Default:** Docker defaults to running as root. Podman defaults to running as your user. This drastically reduces the blast radius of a container breakout.
- **Daemonless:** Docker requires `dockerd` running as root. Podman spawns containers as child processes.
- **Native Secrets:** `podman secret` provides encrypted-at-rest secret storage without external tooling.
- **Systemd Integration:** `podman generate systemd` creates unit files so containers are managed like standard Linux services (start on boot, restart on failure, logs via journald).

## 3. Architecture

### Production with Wasabi Cloud Storage (3 Containers)

```
Internet ──HTTPS/443──▶ Caddy ──HTTP/8080──▶ Arkfile ──TCP/4001──▶ rqlite
                         (public net)         │ (internal net)      (internal net)
                                              │
                                              └──HTTPS──▶ Wasabi Cloud
```

### Self-Hosted with Local S3-Compatible Storage (4 Containers)

```
Internet ──HTTPS/443──▶ Caddy ──HTTP/8080──▶ Arkfile ──TCP/4001──▶ rqlite
                         (public net)         │ (internal net)      (internal net)
                                              │
                                              └──HTTP/9000──▶ MinIO/SeaweedFS
                                                              (internal net)
```

> **Note on MinIO:** MinIO is currently used as the local S3-compatible storage backend. However, MinIO has moved away from open-source licensing (now BSL/AGPL). For future single-node self-hosted deployments, we plan to migrate to [SeaweedFS](https://github.com/seaweedfs/seaweedfs) which provides S3-compatible storage under the Apache 2.0 license. The Arkfile storage layer uses a generic S3 interface (`STORAGE_PROVIDER=generic-s3`), so this migration will be transparent — only the storage container changes, no application code modifications needed.

## 4. Container Specifications

### A. Arkfile (The App) — Alpine Multi-Stage Build

**Why not `FROM scratch`?** Arkfile requires CGO (`CGO_ENABLED=1`) because the OPAQUE authentication protocol is implemented via C FFI bindings to libopaque (which depends on libsodium). A `CGO_ENABLED=0` build would fail to compile. We use Alpine with static linking to keep the image minimal.

```dockerfile
# === STAGE 1: C Library Builder ===
# Build libsodium, liboprf, and libopaque as static libraries
FROM alpine:latest AS clibs
RUN apk add --no-cache gcc musl-dev make git autoconf automake libtool
WORKDIR /build

# Build libsodium (static)
RUN git clone --depth 1 --branch stable https://github.com/jedisct1/libsodium.git && \
    cd libsodium && ./autogen.sh && \
    ./configure --disable-shared --enable-static --prefix=/usr/local && \
    make -j$(nproc) && make install

# Copy and build liboprf + libopaque (static)
COPY vendor/stef/liboprf /build/liboprf
COPY vendor/stef/libopaque /build/libopaque
RUN cd /build/liboprf/src && \
    make SODIUM_PATH=/usr/local && \
    cd /build/libopaque/src && \
    make SODIUM_PATH=/usr/local LIBOPRF_PATH=/build/liboprf/src

# === STAGE 2: Go Builder ===
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev

# Copy static C libraries from stage 1
COPY --from=clibs /usr/local/lib/libsodium.a /usr/local/lib/
COPY --from=clibs /usr/local/include/ /usr/local/include/
COPY --from=clibs /build/libopaque/src/libopaque.a /usr/local/lib/
COPY --from=clibs /build/liboprf/src/liboprf.a /usr/local/lib/
COPY --from=clibs /build/libopaque/src/opaque.h /usr/local/include/
COPY --from=clibs /build/liboprf/src/oprf.h /usr/local/include/

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build with CGO enabled, fully static linking via musl
RUN CGO_ENABLED=1 \
    CGO_CFLAGS="-I/usr/local/include" \
    CGO_LDFLAGS="-L/usr/local/lib -lopaque -loprf -lsodium" \
    go build -ldflags="-s -w -linkmode external -extldflags '-static'" \
    -o /arkfile ./main.go

# === STAGE 3: WASM + Client Assets Builder ===
FROM node:lts-alpine AS assets
WORKDIR /src
COPY client/ ./client/
COPY package.json tsconfig.json ./
# Pre-built WASM (built separately or from CI)
COPY client/static/js/libopaque.js ./client/static/js/
RUN npm install && npm run build

# === STAGE 4: Final Production Image ===
FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 -h /opt/arkfile arkfile

# Copy binary
COPY --from=builder /arkfile /usr/local/bin/arkfile

# Copy client static files (HTML, CSS, JS bundles, WASM)
COPY --from=assets /src/client/static /opt/arkfile/client/static

# Copy embedded config files
COPY crypto/argon2id-params.json /opt/arkfile/crypto/
COPY crypto/password-requirements.json /opt/arkfile/crypto/

# Create runtime directories
RUN mkdir -p /opt/arkfile/var/log /opt/arkfile/etc/keys && \
    chown -R arkfile:arkfile /opt/arkfile

USER 1000
WORKDIR /opt/arkfile

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/readyz | grep -q '"status":"ready"' || exit 1

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/arkfile"]
```

### B. rqlite (The DB) — `FROM scratch`

rqlite is pure Go — `CGO_ENABLED=0` works perfectly. This is a true minimal scratch build.

```dockerfile
# === STAGE 1: Builder ===
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 --branch v9.4.1 https://github.com/rqlite/rqlite.git . && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /rqlited ./cmd/rqlited && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /rqlite ./cmd/rqlite

# === STAGE 2: Harvester ===
FROM alpine:latest AS harvester
RUN apk add --no-cache ca-certificates tzdata && \
    echo "rqlite:x:1000:1000:rqlite:/:" > /etc/passwd_minimal

# === STAGE 3: Final (Scratch) ===
FROM scratch
COPY --from=builder /rqlited /bin/rqlited
COPY --from=builder /rqlite /bin/rqlite
COPY --from=harvester /etc/passwd_minimal /etc/passwd
COPY --from=harvester /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=harvester /usr/share/zoneinfo /usr/share/zoneinfo

USER 1000
EXPOSE 4001 4002

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/bin/rqlite", "-H", "localhost:4001", "SELECT 1"]

ENTRYPOINT ["/bin/rqlited"]
CMD ["-http-addr", "0.0.0.0:4001", "-raft-addr", "0.0.0.0:4002", "/data"]
```

### C. Caddy (The Proxy) — `caddy:alpine`

We use the official Alpine-based Caddy image. It provides useful debugging tools if network issues arise, and the attack surface is still very small (Alpine, not Debian/Ubuntu).

No custom Dockerfile needed — configured via `Caddyfile` bind mount.

## 5. Secrets Management

### Principle: Never Put Secrets in compose.yaml or Environment Variables

Secrets are injected via **Podman Secrets** (encrypted at rest, mounted as files at `/run/secrets/`). Non-secret configuration uses environment variables.

### Creating Secrets on the Host

```bash
# One-time setup — generate and store secrets
openssl rand -hex 32 | podman secret create arkfile_master_key -
openssl rand -hex 32 | podman secret create rqlite_password -
echo "your-wasabi-access-key" | podman secret create s3_access_key -
echo "your-wasabi-secret-key" | podman secret create s3_secret_key -

# For local storage profile (MinIO/SeaweedFS)
openssl rand -hex 32 | podman secret create minio_root_password -
```

### Reading Secrets in Go (Code Change Required)

Arkfile's config loader needs a small addition to support the `*_FILE` convention (standard Docker/Podman secrets pattern):

```go
// config/config.go
func getSecretOrEnv(envKey string) string {
    // Check for _FILE variant first (Podman/Docker secrets)
    if filePath := os.Getenv(envKey + "_FILE"); filePath != "" {
        data, err := os.ReadFile(filePath)
        if err == nil {
            return strings.TrimSpace(string(data))
        }
    }
    // Fall back to direct env var (bare-metal deployments)
    return os.Getenv(envKey)
}
```

Use `getSecretOrEnv("MASTER_KEY")` instead of `os.Getenv("MASTER_KEY")` for all sensitive values. This is backward-compatible — bare-metal deployments using env vars continue to work unchanged.

### TLS Certificates

TLS certs are multi-file and binary — they work better as read-only bind mounts rather than Podman secrets:

```yaml
volumes:
  - type: bind
    source: ./tls/arkfile
    target: /opt/arkfile/etc/keys/tls
    read_only: true
```

Generate certs on the host using the existing `scripts/setup/04-setup-tls-certs.sh`, then mount them into the container.

### Secret Classification

| Secret Type | Mechanism | Visible in `podman inspect`? |
|---|---|---|
| Master key | Podman Secret → `/run/secrets/` | No |
| DB password | Podman Secret → `/run/secrets/` | No |
| S3 credentials | Podman Secret → `/run/secrets/` | No |
| TLS certs/keys | Read-only bind mount | Mount path visible, content not |
| Non-secret config | Environment variables | Yes (fine — not sensitive) |

## 6. Orchestration (`compose.yaml`)

```yaml
services:
  # === 1. Reverse Proxy (public-facing) ===
  caddy:
    image: caddy:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - public
      - internal
    restart: always
    healthcheck:
      test: ["CMD", "caddy", "version"]
      interval: 30s
      timeout: 5s
      retries: 3

  # === 2. Database ===
  rqlite:
    build:
      context: .
      dockerfile: Dockerfile.rqlite
    volumes:
      - rqlite_data:/data
    networks:
      - internal
    restart: always
    # HEALTHCHECK defined in Dockerfile

  # === 3. Application ===
  arkfile:
    build:
      context: .
      dockerfile: Dockerfile
    secrets:
      - arkfile_master_key
      - rqlite_password
      - s3_access_key
      - s3_secret_key
    environment:
      # Non-secret configuration
      - DATABASE_TYPE=rqlite
      - RQLITE_ADDRESS=http://rqlite:4001
      - RQLITE_USERNAME=arkfile
      - PORT=8080
      - TLS_ENABLED=true
      - TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/server-cert.pem
      - TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/server-key.pem
      # Secret file references (read by getSecretOrEnv)
      - MASTER_KEY_FILE=/run/secrets/arkfile_master_key
      - RQLITE_PASSWORD_FILE=/run/secrets/rqlite_password
      - S3_ACCESS_KEY_FILE=/run/secrets/s3_access_key
      - S3_SECRET_KEY_FILE=/run/secrets/s3_secret_key
      # Storage config (non-secret)
      - STORAGE_PROVIDER=wasabi
      - S3_ENDPOINT=s3.wasabisys.com
      - S3_BUCKET=your-bucket-name
      - S3_REGION=us-east-1
    volumes:
      - type: bind
        source: ./tls/arkfile
        target: /opt/arkfile/etc/keys/tls
        read_only: true
    networks:
      - internal
    depends_on:
      rqlite:
        condition: service_healthy
    restart: always
    # HEALTHCHECK defined in Dockerfile

  # === 4. Local S3 Storage (optional profile) ===
  # Activate with: podman-compose --profile local-storage up -d
  #
  # NOTE: MinIO is used currently but is no longer open source (BSL/AGPL).
  # We plan to migrate to SeaweedFS (Apache 2.0) for single-node self-hosted
  # deployments. The Arkfile storage layer uses generic S3, so this migration
  # only requires swapping this container — no application code changes.
  minio:
    image: minio/minio:latest
    profiles: ["local-storage"]
    command: server /data --console-address ":9001"
    secrets:
      - minio_root_password
    environment:
      - MINIO_ROOT_USER=arkfile
      - MINIO_ROOT_PASSWORD_FILE=/run/secrets/minio_root_password
    volumes:
      - minio_data:/data
    networks:
      - internal
    restart: always
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 30s
      timeout: 5s
      retries: 3

# === Network Segmentation ===
networks:
  public:
    driver: bridge
    # Caddy needs internet access for ACME cert renewal
  internal:
    driver: bridge
    internal: true
    # App, DB, and storage communicate here — no internet access

# === Persistent Volumes ===
volumes:
  caddy_data:
  caddy_config:
  rqlite_data:
  minio_data:

# === Podman Secrets (must be created before first run) ===
secrets:
  arkfile_master_key:
    external: true
  rqlite_password:
    external: true
  s3_access_key:
    external: true
  s3_secret_key:
    external: true
  minio_root_password:
    external: true
```

## 7. Deployment

### Prerequisites

```bash
# Install Podman
sudo apt install podman podman-compose    # Debian/Ubuntu
sudo dnf install podman podman-compose    # Fedora/RHEL

# Enable rootless Podman socket (for compose compatibility)
systemctl --user enable --now podman.socket
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
```

### First-Time Setup

```bash
# 1. Generate TLS certificates
mkdir -p tls/arkfile
./scripts/setup/04-setup-tls-certs.sh  # Generates certs into tls/arkfile/

# 2. Create Podman secrets
openssl rand -hex 32 | podman secret create arkfile_master_key -
openssl rand -hex 32 | podman secret create rqlite_password -
# For Wasabi:
echo "your-wasabi-access-key" | podman secret create s3_access_key -
echo "your-wasabi-secret-key" | podman secret create s3_secret_key -
# For local storage:
openssl rand -hex 32 | podman secret create minio_root_password -

# 3. Build and start (Wasabi mode)
podman-compose up -d --build

# 3. OR: Build and start (local storage mode)
podman-compose --profile local-storage up -d --build
```

### Making It Persistent (Systemd Integration)

```bash
# Generate systemd unit files from running containers
podman generate systemd --new --name arkfile --files
podman generate systemd --new --name rqlite --files
podman generate systemd --new --name caddy --files

# Install to user systemd
mkdir -p ~/.config/systemd/user/
mv *.service ~/.config/systemd/user/

# Enable auto-start on boot
systemctl --user daemon-reload
systemctl --user enable container-arkfile.service
systemctl --user enable container-rqlite.service
systemctl --user enable container-caddy.service

# Enable lingering (so services run even when user is logged out)
loginctl enable-linger $USER
```

### Monitoring

```bash
# Check health of all containers
podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check Arkfile readiness
curl -s http://localhost:8080/readyz | jq .

# View logs
podman logs -f arkfile
podman logs -f rqlite
podman logs -f caddy

# Or via journald (if systemd services are configured)
journalctl --user -u container-arkfile.service -f
```

### Updating

```bash
# Pull latest code, rebuild, and restart
git pull
podman-compose down
podman-compose up -d --build
```

## 8. Admin Bootstrap (Production)

In production, there is **no dev admin user** seeded automatically. The first admin is bootstrapped via the admin bootstrap flow:

1. Set `ARKFILE_FORCE_ADMIN_BOOTSTRAP=true` in the container environment
2. Start the container
3. Use `arkfile-admin bootstrap` CLI to create the initial admin
4. Remove `ARKFILE_FORCE_ADMIN_BOOTSTRAP` and restart

See `docs/wip/admin-bootstrap.md` for the full procedure.

## 9. Future: SeaweedFS Migration

For self-hosted single-node deployments, MinIO will be replaced with [SeaweedFS](https://github.com/seaweedfs/seaweedfs):

- **Why:** MinIO moved to BSL/AGPL licensing — no longer truly open source
- **SeaweedFS:** Apache 2.0 license, S3-compatible API, designed for single-node and small-cluster use
- **Impact:** Only the storage container in `compose.yaml` changes. Arkfile's `STORAGE_PROVIDER=generic-s3` interface remains the same
- **Timeline:** Planned for a future release. The storage abstraction layer is already generic S3, so the migration is straightforward
