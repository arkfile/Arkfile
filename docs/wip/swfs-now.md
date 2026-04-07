# SeaweedFS Migration: Implementation Plan

## Overview

This document is the implementation plan for replacing MinIO with SeaweedFS as Arkfile's local S3-compatible storage backend. MinIO's AGPL license is a concern for any deployment (even beta), and SeaweedFS (Apache 2.0) is a clean alternative. The Arkfile storage layer already uses `STORAGE_PROVIDER=generic-s3` with the AWS SDK v2 -- there is zero MinIO-specific application code. This migration is purely infrastructure: new setup script, new systemd service, updated secrets.env generation in orchestrator scripts.

## Why Now

- MinIO moved to AGPL-3.0 in 2021, creating licensing ambiguity for any deployment that serves users
- Arkfile's storage layer is already fully generic S3 (AWS SDK v2, no MinIO Go SDK imports)
- Doing this before creating `local-deploy.sh` and `test-deploy.sh` means those scripts are born clean with SeaweedFS
- The migration is scoped and testable: `dev-reset.sh` + `e2e-test.sh` prove correctness

## SeaweedFS Architecture (Single Binary Mode)

For Arkfile's single-node deployments (dev, local, beta), SeaweedFS runs in "single binary" mode:

```
weed server -dir=/data -s3 -s3.port=9332
```

This starts Master + Volume + Filer + S3 Gateway in one process. The S3 gateway speaks standard AWS S3 API on port 9332, which is all Arkfile needs.

### Port Assignments

| Service | Port | Binding | Purpose |
|---|---|---|---|
| S3 Gateway | 9332 | 127.0.0.1 only | S3-compatible API (Arkfile connects on localhost) |
| Filer UI | 9333 | 127.0.0.1 only | Admin/debug UI (localhost only, not exposed) |
| Master | 9334 | 127.0.0.1 only | Cluster management (internal) |
| Volume gRPC | 18080 | 127.0.0.1 only | Volume server gRPC (internal) |

Note: SeaweedFS defaults to 8333 for S3, but we use 9332 to avoid conflict with Bitcoin Core's default P2P port (8333). All SeaweedFS services (including the S3 gateway) are bound to 127.0.0.1 only -- Arkfile connects to S3 on localhost and there is no scenario where external network access to the S3 API is needed.

## Scope of Changes

### Application Code Changes: NONE

The Go storage layer (`storage/s3.go`) uses AWS SDK v2 with a configurable `S3_ENDPOINT`. It does not import or reference MinIO's Go SDK. SeaweedFS's S3 gateway speaks the same AWS S3 API. The only thing that changes is the endpoint URL in config.

### Go Code Comment Updates (Cosmetic)

7 occurrences of "MinIO" or "minio" in Go files, all in comments or test env vars:

| File | Type | Change |
|---|---|---|
| `storage/storage.go` | Comment | "initialized with Minio or mock" -> "initialized with S3-compatible backend or mock" |
| `config/config.go` | Comment | "MinIO, SeaweedFS, Ceph" -> "SeaweedFS, Ceph, MinIO" (reorder) |
| `monitoring/key_health.go` | Health check entry | "MinIO TLS Certificate" -> "Storage TLS Certificate", update path |
| `models/user_test.go` | Test env var | `STORAGE_PROVIDER=local` + `MINIO_ROOT_USER` -> update comments |
| `auth/jwt_test.go` | Test env var | Same as above |
| `handlers/handlers_test.go` | Import comment | "Import minio" -> remove stale comment |

### Infrastructure Changes

| Component | Current (MinIO) | New (SeaweedFS) |
|---|---|---|
| **Binary** | `minio` (pre-built download) | `weed` (pre-built download or build from source) |
| **Setup script** | `scripts/setup/05-setup-minio.sh` | `scripts/setup/05-setup-seaweedfs.sh` (new) |
| **Systemd service** | `systemd/minio.service` | `systemd/seaweedfs.service` (new) |
| **S3 port** | 9000 | 9332 |
| **Admin UI port** | 9001 (MinIO Console) | 9333 (Filer UI, localhost only) |
| **Auth mechanism** | `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` env vars | S3 config file (`-s3.config`) with access/secret keys |
| **Data directory** | `/opt/arkfile/var/lib/minio/data` | `/opt/arkfile/var/lib/seaweedfs/data` |
| **Health check** | `curl http://localhost:9000/minio/health/ready` | `curl http://localhost:9332/status` |

### Scripts That Need Updates

| Script | Change Required |
|---|---|
| `scripts/dev-reset.sh` | Call `05-setup-seaweedfs.sh` instead of `05-setup-minio.sh`; update secrets.env generation (S3_ENDPOINT port, remove MINIO_* vars); update service start/stop/health for seaweedfs; update nuke step data paths |
| `scripts/testing/e2e-test.sh` | Update any MinIO-specific health checks or references |
| `scripts/testing/e2e-playwright.sh` | Same as above (if applicable) |
| `scripts/maintenance/health-check.sh` | Update storage health check endpoint |
| `scripts/maintenance/download-minio.sh` | Replace with `download-seaweedfs.sh` or remove |

### Files to Create

1. **`scripts/setup/05-setup-seaweedfs.sh`** -- Download/install SeaweedFS, create data dirs, install systemd service
2. **`systemd/seaweedfs.service`** -- Systemd unit for SeaweedFS single-binary mode

### Files to Delete/Archive

1. **`scripts/setup/05-setup-minio.sh`** -- Move to `scripts/wip/` initially, delete after migration is proven
2. **`systemd/minio.service`** -- Move to `scripts/wip/` initially, delete after migration is proven
3. **`scripts/maintenance/download-minio.sh`** -- Move to `scripts/wip/`

## Detailed Implementation

### 1. scripts/setup/05-setup-seaweedfs.sh

```
Purpose: Download SeaweedFS binary, create directories, install systemd service
Model after: 05-setup-minio.sh (same structure)

Steps:
- Determine latest stable SeaweedFS version (or pin a specific version)
- Download pre-built linux-amd64 binary from GitHub releases
  URL pattern: https://github.com/seaweedfs/seaweedfs/releases/download/<version>/linux_amd64.tar.gz
- Extract `weed` binary to /usr/local/bin/weed
- Set permissions: chmod 755 /usr/local/bin/weed
- Create data directories:
  /opt/arkfile/var/lib/seaweedfs
  /opt/arkfile/var/lib/seaweedfs/data
- Set ownership: arkfile:arkfile
- Copy systemd/seaweedfs.service to /etc/systemd/system/
- Reload systemd daemon
- Verify installation: weed version
```

### 2. systemd/seaweedfs.service

```ini
[Unit]
Description=SeaweedFS Server (S3-compatible storage)
Documentation=https://github.com/seaweedfs/seaweedfs
After=network.target

[Service]
Type=simple
User=arkfile
Group=arkfile
WorkingDirectory=/opt/arkfile/var/lib/seaweedfs
EnvironmentFile=/opt/arkfile/etc/secrets.env

ExecStart=/usr/local/bin/weed server \
    -dir=/opt/arkfile/var/lib/seaweedfs/data \
    -s3 \
    -s3.port=9332 \
    -s3.config=/opt/arkfile/etc/seaweedfs-s3.json \
    -master.port=9334 \
    -volume.port=18080 \
    -filer.port=9333 \
    -ip.bind=127.0.0.1 \
    -s3.ip.bind=127.0.0.1

Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Key design decisions:
- `-ip.bind=127.0.0.1` binds Master, Volume, and Filer to localhost only
- `-s3.ip.bind=127.0.0.1` binds S3 gateway to localhost only (Arkfile connects via `S3_ENDPOINT=http://localhost:9332`; no external access needed)
- `-s3.config` points to a JSON file with S3 access credentials

### 3. SeaweedFS S3 Auth Config

SeaweedFS S3 gateway uses a JSON config file for S3 credentials (not env vars like MinIO).

Generate `/opt/arkfile/etc/seaweedfs-s3.json`:

```json
{
  "identities": [
    {
      "name": "arkfile",
      "credentials": [
        {
          "accessKey": "<S3_ACCESS_KEY from secrets.env>",
          "secretKey": "<S3_SECRET_KEY from secrets.env>"
        }
      ],
      "actions": [
        "Admin",
        "Read",
        "Write",
        "List",
        "Tagging"
      ]
    }
  ]
}
```

This file must be generated by the orchestrator scripts (`dev-reset.sh`, `local-deploy.sh`, `test-deploy.sh`) alongside `secrets.env`, using the same randomly generated S3 credentials.

### 4. secrets.env Changes

Remove MinIO-specific vars, update S3 endpoint port:

**Before (MinIO):**
```
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=arkfile-dev
S3_SECRET_KEY=<random>
S3_BUCKET=arkfile-dev
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
S3_USE_SSL=false

MINIO_ROOT_USER=arkfile-dev
MINIO_ROOT_PASSWORD=<same as S3_SECRET_KEY>
MINIO_SSE_AUTO_ENCRYPTION=off
```

**After (SeaweedFS):**
```
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=http://localhost:9332
S3_ACCESS_KEY=arkfile-dev
S3_SECRET_KEY=<random>
S3_BUCKET=arkfile-dev
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
S3_USE_SSL=false
```

The `MINIO_*` vars are completely removed. SeaweedFS S3 auth is configured via the JSON config file, not env vars.

### 5. dev-reset.sh Changes

Specific lines that change (by step number in the current script):

**Step 1 (service shutdown):**
- `stop_service_if_running "minio"` -> `stop_service_if_running "seaweedfs"`
- `pkill -f "minio"` -> `pkill -f "weed"`

**Step 2 (data destruction):**
- `rm -rf "$ARKFILE_DIR/var/lib/"*/minio/data/*` -> `rm -rf "$ARKFILE_DIR/var/lib/seaweedfs/data"/*`

**Step 5 (secrets generation):**
- Change `S3_ENDPOINT=http://localhost:9000` -> `S3_ENDPOINT=http://localhost:9332`
- Remove all `MINIO_*` lines
- Add generation of `/opt/arkfile/etc/seaweedfs-s3.json`

**Step 7 (setup storage):**
- `./scripts/setup/05-setup-minio.sh` -> `./scripts/setup/05-setup-seaweedfs.sh`

**Step 8 (start services):**
- `systemctl start minio` / `systemctl enable minio` -> `systemctl start seaweedfs` / `systemctl enable seaweedfs`
- Health check: `systemctl is-active minio` -> `systemctl is-active seaweedfs`

**Step 9 (health verification):**
- `minio_status` -> `seaweedfs_status`
- `systemctl is-active minio` -> `systemctl is-active seaweedfs`
- Final status output: "MinIO" -> "SeaweedFS"

**Success message:**
- Update all "MinIO" references to "SeaweedFS"

### 6. e2e-test.sh / e2e-playwright.sh Changes

Search for any MinIO-specific health checks, service references, or port 9000 references and update to SeaweedFS/9332.

### 7. monitoring/key_health.go Changes

Update the storage TLS certificate health check entry (if applicable -- MinIO TLS may not be used in dev mode).

## Implementation Order

This is designed so that each step can be tested before moving to the next:

1. **Create `scripts/setup/05-setup-seaweedfs.sh`** -- Can test standalone: `sudo bash scripts/setup/05-setup-seaweedfs.sh` should download and install SeaweedFS
2. **Create `systemd/seaweedfs.service`** -- Can test standalone: start the service, verify S3 endpoint responds
3. **Update `dev-reset.sh`** -- The main integration point. After this, run `dev-reset.sh` and verify the NUKE + rebuild + start cycle works
4. **Run `e2e-test.sh`** -- The proof. If all e2e tests pass with SeaweedFS, the migration is complete
5. **Run `e2e-playwright.sh`** -- Browser-level verification
6. **Update Go comments** -- Cosmetic cleanup
7. **Move MinIO files to `scripts/wip/`** -- `05-setup-minio.sh`, `minio.service`, `download-minio.sh`
8. **Update `monitoring/key_health.go`** -- Storage cert health check name/path
9. **Update documentation** -- `seaweedfs-notes.md` can be archived, update `scripts-guide.md`

## Risk Assessment

### Known Risk: Multipart Upload Compatibility

SeaweedFS's S3 gateway implements the AWS S3 multipart upload API, but edge cases in ETag formatting, part number handling, or completion responses could differ from MinIO. The e2e tests exercise chunked uploads (including the 100MB test) thoroughly, so any incompatibility will surface immediately.

**Mitigation:** Run e2e tests after step 4. If multipart uploads fail, investigate SeaweedFS S3 gateway configuration options or adjust the upload logic (unlikely to be needed).

### Known Risk: Bucket Auto-Creation

Arkfile's `storage/s3.go` auto-creates the bucket if it doesn't exist (for `ProviderGenericS3`). SeaweedFS's S3 gateway supports bucket creation via the S3 API, so this should work. Verify in e2e tests.

### Known Risk: S3 Config File Permissions

The `seaweedfs-s3.json` file contains S3 access credentials. Must be:
- Owned by `arkfile:arkfile`
- Permissions `640`
- Generated by orchestrator scripts (not committed to repo)

### Low Risk: Data Path Changes

The data directory changes from `/opt/arkfile/var/lib/minio/data` to `/opt/arkfile/var/lib/seaweedfs/data`. Since `dev-reset.sh` nukes all data anyway, there's no migration concern for dev. For future `local-deploy.sh` and `test-deploy.sh`, the constructive scripts will create the new path from scratch.

## SeaweedFS Version Pinning

Pin to a specific stable release for reproducibility. As of this writing, use the latest stable from https://github.com/seaweedfs/seaweedfs/releases. The setup script should have a `SEAWEEDFS_VERSION` variable at the top, similar to how `05-setup-minio.sh` pins `MINIO_VERSION`.

## Estimated Effort

| Task | Time |
|---|---|
| Write `05-setup-seaweedfs.sh` | 1 hour |
| Write `systemd/seaweedfs.service` | 15 min |
| Update `dev-reset.sh` | 30 min |
| Test with `e2e-test.sh` + debug | 1-2 hours |
| Update Go comments | 15 min |
| Move MinIO files, update docs | 30 min |
| **Total** | **3-4 hours** |

## Post-Migration Cleanup

After SeaweedFS is proven (all e2e tests passing):

1. Delete `scripts/wip/05-setup-minio.sh` (was moved from `scripts/setup/`)
2. Delete `scripts/wip/minio.service` (was moved from `systemd/`)
3. Delete `scripts/maintenance/download-minio.sh`
4. Archive `docs/wip/seaweedfs-notes.md` to `docs/wip/archive/`
5. Update `docs/scripts-guide.md` to reference SeaweedFS instead of MinIO
6. Update `docs/wip/podman.md` to reference SeaweedFS container instead of MinIO container
7. Update `docs/wip/test-deploy.md` to reference SeaweedFS instead of MinIO
8. Update `docs/wip/local-deploy.md` to reference SeaweedFS instead of MinIO
