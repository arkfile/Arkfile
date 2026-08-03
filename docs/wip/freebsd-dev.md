# FreeBSD Development Reset Path

## Reasoning

FreeBSD is a strong next host target for Arkfile’s development and self-hosted deploy path. It is a mature open-source Unix with a clear base-versus-ports split, first-class ZFS, and no dependency on systemd, which matches operators who want a small, auditable service model (`rc.d`) and storage that can add redundancy and resilience under a local SeaweedFS backend. Bringing `dev-reset` up there forces the deploy scripts to separate “run Arkfile” from “run on Linux systemd,” which is useful even for Linux, and it is a practical step before harder ports such as OpenBSD. The goal of this WIP is not a FreeBSD ports package or a production Caddy path; it is proving the same privacy-preserving stack can be built, reset, and e2e-tested on FreeBSD amd64 with shared scripts and thin OS adapters.

## Status

Draft planning document. Design decisions below are locked for the first FreeBSD bring-up. No FreeBSD-specific deploy/runtime code has been written yet. The C/Go build layer already has partial FreeBSD awareness in `scripts/setup/build-config.sh` and related C-library scripts; the gap is the `dev-reset` orchestration, service management, user creation, SeaweedFS download, and GNU/BSD tool seams.

## Overview

Arkfile's development iteration loop today is Linux- and systemd-centric. `sudo bash scripts/dev-reset.sh` stops services, nukes data under `/opt/arkfile`, rebuilds (including vendored OPAQUE/FIDO C libraries and TypeScript), redeploys, regenerates secrets/keys, installs SeaweedFS and rqlite, and starts `seaweedfs` / `rqlite` / `arkfile` via `systemctl`. The Go application, client-side crypto, and most of `build.sh` are not inherently Linux-bound, but the reset/deploy/runtime scripts assume systemd, Linux `useradd`/`groupadd`, GNU coreutils (`sha256sum`, `stat -c`), a `sudo` + `$SUDO_USER` privilege model, and a hardcoded SeaweedFS `linux_amd64` release asset.

The goal of this WIP is a FreeBSD amd64 path that reuses the same `dev-reset.sh` entrypoint and shared setup scripts, with thin OS adapters and FreeBSD `rc.d` service scripts. A standalone forked `freebsd-dev-reset.sh` is rejected because secrets generation, health checks, nuke steps, and build flags would drift from Linux. OpenBSD, Alpine/OpenRC, production Caddy deploy, and Playwright browser e2e are explicitly out of scope here.

Success for this WIP is: on a FreeBSD amd64 host, as root, run `dev-reset.sh` (with a resolved non-root dev user for builds), then pass `scripts/testing/e2e-test.sh`. Linux remains the primary supported deploy host until that bar is green; docs should say so honestly.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Shape | Shared `scripts/dev-reset.sh` + OS adapters; no standalone FreeBSD fork of the full reset script |
| Adapter location | New `scripts/setup/os-portable.sh`, sourced by `dev-reset.sh`, `deploy-common.sh`, and setup scripts that need service/user/tool shims |
| Service model | New `rc.d/` tree parallel to `systemd/` for `arkfile`, `rqlite`, and `seaweedfs` (same process args as today's unit files) |
| Install root | `/opt/arkfile` on FreeBSD as on Linux (path parity in secrets, units/rc scripts, and docs) |
| Binary install paths | `/usr/local/bin/weed`, `/usr/local/bin/rqlited`, `/usr/local/bin/rqlite` |
| Build root | `/var/tmp/arkfile-build` (already the shared default) |
| Architecture | FreeBSD amd64 only for v1 |
| Privilege | FreeBSD path requires root (`EUID=0`). Do not require the `sudo` package. |
| Dev user for builds | Resolve non-root build/ownership user as: `--dev-user` / `ARKFILE_DEV_USER`, else `$SUDO_USER` if set, else fail with a clear error. Never run Go/bun builds as root by falling back to root. |
| Shell | Keep bash; FreeBSD hosts must `pkg install bash` (shebang remains `#!/bin/bash` or PATH-resolved bash) |
| Users/groups | FreeBSD branch in `01-setup-users.sh` via `pw groupadd` / `pw useradd`, shell `/usr/sbin/nologin` |
| SeaweedFS | Platform-keyed release asset (`freebsd_amd64.tar.gz`) and pinned SHA-256 digest map in `05-setup-seaweedfs.sh` |
| rqlite | Keep build-from-source (`06-setup-rqlite-build.sh`); install FreeBSD `rc.d` instead of only warning when systemd is absent |
| Server linking | Fully static server binary required on FreeBSD, same verification intent as Linux. No dynamic fallback in this WIP. If a real host proves full static impossible, stop and record evidence as a new decision; do not silently weaken the check. Vendored crypto (libopaque / liboprf / libsodium) must never be loaded as ports shared libraries. |
| Tool shims | `sha256_file`, `stat_owner`, `mktemp_file` (and similar) in `os-portable.sh`; replace bare GNU-only call sites as needed for FreeBSD |
| Bun | Hard prerequisite; fail fast with install guidance if missing |
| WASM / emsdk | Keep existing emsdk path; document FreeBSD host deps; treat availability as a known risk, not a redesign |
| TypeScript assets | Must be built on the FreeBSD host via bun; do not ship or reuse Linux-built `dist/` as a supported path |
| e2e success bar | FreeBSD `dev-reset` then green `scripts/testing/e2e-test.sh` (curl + `arkfile-client`) |
| Playwright | Out of scope for this WIP |
| local-deploy / prod-deploy / Caddy | Out of scope for this WIP |
| OpenBSD | Explicit non-goal; follow-on only after FreeBSD is green |
| Docs honesty | Until e2e is green: Linux is the supported deploy host; FreeBSD `dev-reset` is experimental/WIP. Update `AGENTS.md` and `docs/setup.md` accordingly when implementing and again when complete. |

## Privilege Model (FreeBSD)

FreeBSD base does not ship `sudo`. Operators may use root login, `su`, packaged `sudo`/`doas`, or other means. The FreeBSD path only requires that the process is already root.

Documented invocations:

```bash
# Preferred FreeBSD form (root shell via su / console / etc.)
ARKFILE_DEV_USER=adam bash scripts/dev-reset.sh

# Equivalent with explicit flag (when implemented)
bash scripts/dev-reset.sh --dev-user adam

# If the operator has installed sudo and prefers it (optional, not required)
sudo bash scripts/dev-reset.sh
```

When `$SUDO_USER` is unset and neither `--dev-user` nor `ARKFILE_DEV_USER` is provided, abort before mutating the system. Linux may keep today's `sudo`-oriented messaging; FreeBSD messaging must describe root + dev-user resolution.

## Current Call Graph (Linux baseline)

```
scripts/dev-reset.sh
├── scripts/setup/build-config.sh
├── scripts/setup/deploy-common.sh
├── stop services (systemctl) + pkill
├── nuke /opt/arkfile data + /tmp/arkfile-e2e-test-data
├── run_as_user ./scripts/setup/build.sh --build-only
├── ./scripts/setup/01-setup-users.sh
├── ./scripts/setup/02-setup-directories.sh
├── ./scripts/setup/deploy.sh          # copies systemd units
├── secrets / seaweedfs-s3.json / rqlite-auth.json
├── ./scripts/setup/03-setup-master-key.sh
├── ./scripts/setup/04-setup-tls-certs.sh
├── ./scripts/setup/05-setup-seaweedfs.sh   # linux_amd64 tarball today
├── ./scripts/setup/06-setup-rqlite-build.sh
└── systemctl start/enable seaweedfs, rqlite, arkfile + health checks
```

FreeBSD keeps this step order. Only the OS seams behind stop/start/enable, user creation, unit install, SeaweedFS asset selection, checksum/stat helpers, and privilege/dev-user resolution change.

## What Already Helps

`build-config.sh` already normalizes `FreeBSD` into `BUILD_OS=freebsd`, prefers `gmake`, can use `sysctl hw.ncpu`, maps OpenSSL Configure targets for FreeBSD, and prints FreeBSD package hints. `build-libopaque.sh` / `build-libfido2.sh` already treat FreeBSD as a supported C build OS. `06-setup-rqlite-build.sh` already has a `pkg` dependency branch and soft-fails systemd install with a manual rc.d note. Those pieces are starting points, not a complete FreeBSD reset path.

## Implementation Outline

### 1. `scripts/setup/os-portable.sh`

Add a small shared adapter (no Phase/Tier names in code). Responsibilities:

- Detect OS via existing `detect_build_platform` / `uname` (reuse `BUILD_OS` from `build-config.sh` where already sourced).
- Resolve `ARKFILE_DEV_USER` / `--dev-user` / `$SUDO_USER` into `ORIGINAL_USER` (and uid/gid) for ownership and `run_as_user`.
- On FreeBSD: require `EUID=0`; require a resolved non-root dev user; error clearly otherwise.
- Service API used by reset/deploy: `service_stop`, `service_start`, `service_enable`, `service_is_active`, `service_daemon_reload` (no-op or `service` refresh on FreeBSD), `service_logs_hint`.
- Tool shims: `sha256_file`, `stat_owner`, `mktemp_file` (and any other GNU-only helpers found during bring-up).
- Reject unsupported OS early with a message that lists Linux (supported) and FreeBSD (experimental when this WIP lands).

### 2. FreeBSD `rc.d` scripts

Add `rc.d/arkfile`, `rc.d/rqlite`, `rc.d/seaweedfs` with the same executable paths, bind addresses, config files, and working directories as `systemd/*.service` today:

- arkfile: `/opt/arkfile/bin/arkfile`, `EnvironmentFile` equivalent via sourcing or `daemon` env, user/group `arkfile`
- rqlite: `/usr/local/bin/rqlited` with the existing localhost raft/http args and auth file
- seaweedfs: `/usr/local/bin/weed server` with the existing localhost S3/master/volume/filer ports and config path

Install into `/usr/local/etc/rc.d/` (or the FreeBSD-conventional location chosen during implementation; document the choice in this file when fixed). Enable via `sysrc` / `service … enable` patterns appropriate to FreeBSD. Logging: no journald; rc scripts should write to files under `/opt/arkfile/var/log/` (or document syslog), and `service_logs_hint` must point operators there instead of `journalctl`.

Do not invent FreeBSD equivalents of every systemd hardening knob in v1. Prefer application-level controls already present (loopback binds, core dump suppression where portable). Note in code comments only what is intentionally deferred.

### 3. Wire service control through the adapter

Replace direct `systemctl` / `journalctl` call sites in:

- `scripts/dev-reset.sh`
- `scripts/setup/deploy-common.sh` (`stop_service_if_running`)
- `scripts/setup/deploy.sh` (unit install + enable)
- `scripts/setup/06-setup-rqlite-build.sh` (service install branch)
- `scripts/setup/05-setup-seaweedfs.sh` if it installs or enables a unit

Linux behavior must remain unchanged for existing systemd hosts.

### 4. Users and directories

- `01-setup-users.sh`: FreeBSD branch using `pw`; keep Linux `groupadd`/`useradd`.
- `02-setup-directories.sh`: fix GNU-only `dd` flags if they break on FreeBSD; keep layout under `/opt/arkfile`.
- Ownership helpers: use resolved `ORIGINAL_USER` / `arkfile` consistently; avoid assuming `chown user:user` group name equals username if FreeBSD primary group differs (prefer explicit group from `id`).

### 5. SeaweedFS on FreeBSD

In `05-setup-seaweedfs.sh`:

- Select asset from `BUILD_OS`/`BUILD_ARCH` (v1: `freebsd_amd64` only besides existing Linux).
- Pin a separate SHA-256 for the FreeBSD tarball (do not reuse the Linux digest).
- Use `sha256_file` shim instead of bare `sha256sum`.
- Keep install destination `/usr/local/bin/weed`.

### 6. rqlite on FreeBSD

- Keep source build and existing `pkg` dependency install.
- When systemd is absent, install the FreeBSD `rc.d/rqlite` script and enable it the same way other FreeBSD services are enabled in this WIP.
- Do not require Linux-only static-extld flags on FreeBSD if the script already gates those to Linux; keep the FreeBSD build working and installable.

### 7. Build and link policy

- Bun required before TypeScript build; fail with FreeBSD-oriented install notes.
- emsdk/WASM: document packages (`python3`, etc.); fail clearly if emsdk bootstrap cannot run.
- Server: keep `server_go_ldflags` fully static; run existing static verification on FreeBSD (`file`, and any FreeBSD-appropriate check). If verification fails, abort the build -- do not auto-fallback to dynamic.
- CLI FIDO: continue vendored static crypto + OS dynamic libs (`-lpthread` etc.) already sketched for FreeBSD in `build-config.sh`.
- Replace GNU `stat -c` / `sha256sum` usages in `build.sh` with shims as encountered.

### 8. `dev-reset.sh` FreeBSD entry behavior

- Source `os-portable.sh` early.
- On FreeBSD: require root; resolve dev user; refuse unknown arches other than amd64 for this WIP if desired (or allow detect-and-fail for non-amd64).
- Keep the same NUKE confirmation and step order.
- Process cleanup (`pkill`/`pgrep`) must use FreeBSD-compatible patterns; adjust if `|` or `-f` behavior differs.
- Final status and log hints must be OS-aware.

### 9. Host prerequisites (document in this WIP and later in setup docs)

Minimum FreeBSD amd64 package set for bring-up (refine during implementation):

- `bash`, `git`, `go`, `gmake`, `cmake`, `pkgconf`, `perl5`, `python3`, `autoconf`, `automake`, `libtool`, `curl`, `ca_root_nss`
- Bun installed for the resolved dev user (hard prerequisite)
- Network access for SeaweedFS release download, Go modules if needed, and emsdk

Exact `pkg install ...` line should be updated here once validated on a real host.

### 10. Documentation updates (with the implementation)

- `AGENTS.md`: note Linux as primary deploy host; FreeBSD `dev-reset` experimental; root + `ARKFILE_DEV_USER` on FreeBSD; agents still must not invoke deploy scripts themselves.
- `docs/setup.md`: replace aspirational "BSD supported" with accurate Linux-primary / FreeBSD-experimental wording and FreeBSD package notes for this path.
- When e2e is green, revise status in this file and soften "experimental" only to the extent proven (dev-reset + e2e-test, not prod-deploy).

## Non-Goals

- OpenBSD support
- FreeBSD aarch64
- `local-deploy.sh` / `prod-deploy.sh` / `test-deploy.sh` / Caddy / deSEC on FreeBSD
- Playwright / `e2e-playwright.sh` on FreeBSD
- Official FreeBSD ports/packages packaging
- Requiring or depending on the `sudo` package on FreeBSD
- Pre-approving a dynamically linked server binary
- Rewriting scripts from bash to POSIX sh
- Duplicating the entire setup tree under a `freebsd/` directory

## Implementation Order

1. Add `os-portable.sh` (detect, root check, dev-user resolution, service API stubs, tool shims).
2. Add `rc.d/{arkfile,rqlite,seaweedfs}` with parity to current systemd `ExecStart` args.
3. Wire `deploy-common.sh` / `dev-reset.sh` / `deploy.sh` service stop-start-enable-install through the adapter (Linux unchanged).
4. FreeBSD branch in `01-setup-users.sh`; fix directory/GNU seams in `02-setup-directories.sh` as needed.
5. Platform-keyed SeaweedFS download + FreeBSD SHA-256 in `05-setup-seaweedfs.sh`.
6. rqlite FreeBSD rc.d install path in `06-setup-rqlite-build.sh`.
7. `build.sh` / checksum / `stat` shim call sites; bun and emsdk fail-fast messaging for FreeBSD.
8. Validate fully static server link on a real FreeBSD amd64 host; abort on failure pending a new decision.
9. End-to-end: root `dev-reset.sh` with `ARKFILE_DEV_USER` set, then `e2e-test.sh`.
10. Doc honesty pass (`AGENTS.md`, `docs/setup.md`, this file's Status).

## Exit Criteria

- [ ] `os-portable.sh` exists and FreeBSD root + dev-user resolution works
- [ ] `rc.d` scripts start and stop arkfile, rqlite, and seaweedfs reliably
- [ ] SeaweedFS FreeBSD amd64 asset downloads and verifies against a pinned SHA-256
- [ ] `build.sh --build-only` succeeds on FreeBSD amd64 as the resolved dev user (bun + WASM included)
- [ ] Server binary passes full-static verification on FreeBSD
- [ ] `dev-reset.sh` as root completes and leaves all three services healthy
- [ ] `scripts/testing/e2e-test.sh` passes against that instance
- [ ] `AGENTS.md` and `docs/setup.md` describe Linux-primary / FreeBSD-experimental accurately

## Open Items (do not block starting implementation)

These may be filled in during bring-up without changing locked decisions:

- Exact FreeBSD `pkg install` one-liner validated on 14.x or 15.x
- Exact `rc.d` install directory and `sysrc` variable names
- Whether FreeBSD `pgrep`/`pkill` patterns need small syntax tweaks
- Bun install method that works reliably on FreeBSD amd64 (official install script vs other); must remain a hard host prerequisite
- emsdk bootstrap quirks on FreeBSD (Python version, etc.)

If full-static server linking fails on FreeBSD, that is a **new locked decision** requiring developer sign-off with `file`/`ldd` evidence. Do not treat it as an open item that implementers may silently resolve by allowing dynamic linking.
