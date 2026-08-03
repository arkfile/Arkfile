# FreeBSD Development Reset Path

## Reasoning

FreeBSD is a strong next host target for Arkfile’s development and self-hosted deploy path. It is a mature open-source Unix with a clear base-versus-ports split, first-class ZFS, and no dependency on systemd, which matches operators who want a small, auditable service model (`rc.d`) and storage that can add redundancy and resilience under a local SeaweedFS backend. Bringing `dev-reset` up there forces the deploy scripts to separate “run Arkfile” from “run on Linux systemd,” which is useful even for Linux, and it is a practical step before harder ports such as OpenBSD. The goal of this WIP is not a FreeBSD ports package or a production Caddy path; it is proving the same privacy-preserving stack can be built, reset, and e2e-tested on FreeBSD amd64 with shared scripts and thin OS adapters.

## Status

Draft planning document. Design decisions below are locked for the first FreeBSD bring-up. No FreeBSD-specific deploy/runtime code has been written yet. The initial validation target is FreeBSD 15.1-RELEASE amd64; releases below FreeBSD 15 are unsupported. The C/Go build layer already has partial FreeBSD awareness in `scripts/setup/build-config.sh` and related C-library scripts, but the reset/deploy/runtime path, WASM toolchain, service management, privilege transitions, application memory hardening, SeaweedFS download, e2e script, and GNU/BSD userland seams all require work.

## Overview

Arkfile's development iteration loop today is Linux- and systemd-centric. `sudo bash scripts/dev-reset.sh` stops services, nukes data under `/opt/arkfile`, rebuilds (including vendored OPAQUE/FIDO C libraries and TypeScript), redeploys, regenerates secrets/keys, installs SeaweedFS and rqlite, and starts `seaweedfs` / `rqlite` / `arkfile` via `systemctl`. The Go application, client-side crypto, and most of `build.sh` are not inherently Linux-bound, but the reset/deploy/runtime scripts assume systemd, Linux `useradd`/`groupadd`, GNU coreutils (`sha256sum`, `stat -c`), a `sudo` + `$SUDO_USER` privilege model, and a hardcoded SeaweedFS `linux_amd64` release asset.

The goal of this WIP is a FreeBSD amd64 path that reuses the same `dev-reset.sh` entrypoint and shared setup scripts, with thin OS adapters and FreeBSD `rc.d` service scripts. A standalone forked `freebsd-dev-reset.sh` is rejected because secrets generation, health checks, nuke steps, and build flags would drift from Linux. OpenBSD, Alpine/OpenRC, production Caddy deploy, and Playwright browser e2e are explicitly out of scope here.

Success for this WIP requires both platforms: the existing Linux amd64 `sudo bash scripts/dev-reset.sh` followed by `scripts/testing/e2e-test.sh` must remain green without a changed invocation or weakened linking/service behavior, and FreeBSD 15.1-RELEASE amd64 must complete the same reset and e2e workflow using root orchestration with a resolved non-root dev user for builds and tests. Linux remains the primary supported deploy host until both bars are green; docs should say so honestly.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Shape | Shared `scripts/dev-reset.sh` + OS adapters; no standalone FreeBSD fork of the full reset script |
| Adapter location | New `scripts/setup/os-portable.sh`, sourced by `dev-reset.sh`, `deploy-common.sh`, and setup scripts that need service/user/tool shims |
| Platform model | Detect host OS and service manager independently. Linux/systemd and FreeBSD/rc.d are implemented now; a non-systemd Linux host must fail clearly rather than being mistaken for FreeBSD. |
| Service model | New `rc.d/` tree parallel to `systemd/` for `arkfile`, `rqlite`, and `seaweedfs`, installed under `/usr/local/etc/rc.d` with the same process args as today's unit files |
| Service enablement | `sysrc arkfile_enable=YES`, `sysrc rqlite_enable=YES`, and `sysrc seaweedfs_enable=YES` |
| Service definition owner | `deploy.sh` installs all systemd or rc.d service definitions. SeaweedFS/rqlite setup scripts install binaries and data directories only; remove their duplicate service-definition installation paths. |
| Service logs | FreeBSD rc.d services log under `/opt/arkfile/var/log`; do not rely on syslog or journald for the development path |
| Service safety | rc.d launchers run services as `arkfile`, use reliable pidfiles/supervision, bind rqlite/SeaweedFS to loopback exactly as today, and set `RLIMIT_CORE=0` before exec |
| Install root | `/opt/arkfile` on FreeBSD as on Linux (path parity in secrets, units/rc scripts, and docs) |
| Binary install paths | `/usr/local/bin/weed`, `/usr/local/bin/rqlited`, `/usr/local/bin/rqlite` |
| Build root | `/var/tmp/arkfile-build` (already the shared default) |
| FreeBSD baseline | FreeBSD 15.1-RELEASE amd64 is the initial validation target. Reject FreeBSD major versions below 15 and non-amd64 FreeBSD hosts during preflight. Newer releases remain unvalidated until tested. |
| Privilege | FreeBSD path requires root (`EUID=0`). Do not require the `sudo` package. |
| Privileged execution | Add a shared `run_as_root` helper: execute directly when already root; retain existing sudo behavior for Linux scripts invoked by a non-root operator. Route every `sudo` in the dev-reset call graph through the helper instead of requiring sudo on FreeBSD. |
| Dev user for builds | Resolve non-root build/ownership user as `ARKFILE_DEV_USER`, else `$SUDO_USER` if set, else fail before mutation. Validate that it exists, is not root, has a writable home, and can access the repository. Never run Go/bun/git builds as root. Do not add a `--dev-user` argument in v1. |
| Non-root execution | Add a shared argument-safe `run_as_dev_user` implementation. Linux keeps current `sudo -u` semantics; FreeBSD root uses a base-system mechanism with the dev user's real HOME, uid/gid, working directory, and required environment. Do not construct a shell command from unquoted arguments. |
| Shell | Keep bash; FreeBSD hosts install `bash`, and every shared Bash script in the FreeBSD call graph uses `#!/usr/bin/env bash`. Do not require a `/bin/bash` symlink. |
| Users/groups | FreeBSD branch in `01-setup-users.sh` via `pw groupadd` / `pw useradd`, shell `/usr/sbin/nologin` |
| SeaweedFS | Platform-keyed release asset (`freebsd_amd64.tar.gz`) and pinned SHA-256 digest map in `05-setup-seaweedfs.sh` |
| rqlite | Keep build-from-source (`06-setup-rqlite-build.sh`); `deploy.sh` installs its selected service definition while the rqlite setup script owns only dependencies, source/build cache, binaries, and data directories |
| Server linking | Linux remains fully static with its current flags and verification unchanged. On FreeBSD, vendored libopaque/liboprf/libsodium remain statically embedded while FreeBSD base-system runtime libraries may be dynamic. Verification rejects shared Arkfile crypto libraries and unexpected ports libraries, especially crypto dependencies under `/usr/local/lib`. |
| CLI linking | Extend CLI verification with an explicit FreeBSD base-library set (`libc`, `libthr`, and other evidenced base dependencies). Reject unexpected ports libraries and keep vendored OPAQUE/FIDO/crypto archives static. |
| Go platform functions | Implement FreeBSD user-secret-master protection in build-tagged Go: `mlock`/`munlock`, `MADV_NOCORE`, and process `RLIMIT_CORE=0`, with unit tests. Do not retain the generic non-Linux no-op for FreeBSD. |
| Arkfile env loading | Add explicit Go application support for `ARKFILE_ENV_FILE`. Parse it with the existing `godotenv` dependency before configuration loading, without overriding pre-existing process environment values. FreeBSD rc.d passes only the non-secret path. Never source `secrets.env` as root. |
| Shell tool shims | Use portable shell for bootstrap/host operations needed before Arkfile binaries exist: OpenSSL-backed `sha256_file`, `wc -c`-backed `stat_size`, OS-specific `stat_owner`, portable `mktemp_file`, temporary-file/rename editing instead of `sed -i`, and portable random-file generation. Do not invoke `go run` repeatedly for trivial host utilities. |
| Bun | Native FreeBSD package is a hard prerequisite: `pkg install bun`; fail fast if missing |
| WASM toolchain | Linux keeps the existing pinned emsdk path. FreeBSD uses native `pkg install emscripten`; it must not attempt emsdk installation. Record and validate an explicitly supported FreeBSD Emscripten version against the libopaque/libsodium WASM build. |
| TypeScript assets | Must be built on the FreeBSD host via bun; do not ship or reuse Linux-built `dist/` as a supported path |
| e2e portability | `scripts/testing/e2e-test.sh` is in scope for SHA-256, file-size, prerequisite, and reset-guidance portability. Run it as the non-root dev user after root finishes FreeBSD `dev-reset`. |
| Playwright | Out of scope for this WIP |
| local-deploy / prod-deploy / Caddy | Out of scope for this WIP |
| OpenBSD | Explicit non-goal; follow-on only after FreeBSD is green |
| Devuan / non-systemd Linux | Not an exit criterion for this WIP. Keep OS and service-manager detection separate so a later SysVinit/OpenRC/runit adapter can reuse this work without redesign. |
| Docs honesty | Until e2e is green: Linux is the supported deploy host; FreeBSD `dev-reset` is experimental/WIP. Update `AGENTS.md` and `docs/setup.md` accordingly when implementing and again when complete. |

## Privilege Model (FreeBSD)

FreeBSD base does not ship `sudo`. Operators may use root login, `su`, packaged `sudo`/`doas`, or other means. The FreeBSD path only requires that the process is already root.

Documented invocations:

```bash
# Preferred FreeBSD form (root shell via su / console / etc.)
ARKFILE_DEV_USER=adam bash scripts/dev-reset.sh

# If the operator has installed sudo and prefers it (optional, not required)
sudo bash scripts/dev-reset.sh
```

When `$SUDO_USER` is unset and `ARKFILE_DEV_USER` is not provided, abort before mutating the system. Linux keeps today's `sudo` invocation and semantics; FreeBSD messaging describes root + dev-user resolution. The resolved dev-user identity is computed once and used by `deploy-common.sh`, `build-config.sh`, `build.sh`, `build-libopaque-wasm.sh`, `06-setup-rqlite-build.sh`, and local ownership repair in `dev-reset.sh`.

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

FreeBSD keeps this step order. OS-specific behavior is restricted to explicit host/service-manager branches. Linux defaults, systemd commands, service order, paths, current argument parsing, and fully static server behavior must not change.

## What Already Helps

`build-config.sh` already normalizes `FreeBSD` into `BUILD_OS=freebsd`, prefers `gmake`, can use `sysctl hw.ncpu`, maps OpenSSL Configure targets for FreeBSD, and prints FreeBSD package hints. `build-libopaque.sh` / `build-libfido2.sh` already treat FreeBSD as a supported C build OS. `06-setup-rqlite-build.sh` already has a `pkg` dependency branch and soft-fails systemd install with a manual rc.d note. FreeBSD ports now provide native Bun and Emscripten packages. SeaweedFS 4.18 publishes a `freebsd_amd64.tar.gz` artifact. These pieces are starting points, not a complete FreeBSD reset path.

## Implementation Outline

### `scripts/setup/os-portable.sh`

Add a small shared adapter (no Phase/Tier names in code). Keep host OS and service-manager detection separate. Responsibilities:

- Detect OS via existing `detect_build_platform` / `uname` (reuse `BUILD_OS` from `build-config.sh` where already sourced).
- Detect service manager independently: `systemd` on the existing Linux path and `freebsd-rc` on FreeBSD. An unsupported Linux manager receives a precise error, not a FreeBSD branch.
- Resolve `ARKFILE_DEV_USER` / `$SUDO_USER` into one validated `ORIGINAL_USER`, uid, gid, and home for ownership and non-root execution.
- On FreeBSD: require `EUID=0`, FreeBSD major 15 or newer, amd64, and a resolved non-root dev user; error before mutation otherwise.
- `run_as_root`: direct exec when root; preserve current Linux sudo behavior when a setup script is intentionally run as non-root.
- `run_as_dev_user`: argument-safe privilege drop with the correct home, working directory, and selected environment. Linux retains current `sudo -u` semantics; FreeBSD uses a base-system mechanism.
- Service API used by reset/deploy: `service_stop`, `service_start`, `service_enable`, `service_is_active`, `service_install_definition`, `service_daemon_reload`, and `service_logs_hint`.
- Tool shims: `sha256_file`, `stat_size`, `stat_owner`, `mktemp_file`, portable in-place rewrite, and portable random-file output.
- Reject unsupported OS/service-manager combinations early.

Route all privilege and dev-user logic in the call graph through these helpers. This includes `deploy-common.sh`, `build-config.sh`, `dev-reset.sh`'s local ownership helper, `build.sh`, `build-libopaque-wasm.sh`, `01` through `06` setup scripts, and `deploy.sh`. Do not leave independent `$SUDO_USER` interpretations in component scripts.

### FreeBSD `rc.d` scripts

Add `rc.d/arkfile`, `rc.d/rqlite`, `rc.d/seaweedfs` with the same executable paths, bind addresses, config files, and working directories as `systemd/*.service` today:

- arkfile: `/opt/arkfile/bin/arkfile`, non-secret `ARKFILE_ENV_FILE=/opt/arkfile/etc/secrets.env`, user/group `arkfile`
- rqlite: `/usr/local/bin/rqlited` with the existing localhost raft/http args and auth file
- seaweedfs: `/usr/local/bin/weed server` with the existing localhost S3/master/volume/filer ports and config path

Install into `/usr/local/etc/rc.d/` and enable with explicit `sysrc <service>_enable=YES`. Use FreeBSD `rc.subr` and `daemon` patterns with pidfiles that make status/stop/restart reliable. Service output goes to per-service files under `/opt/arkfile/var/log/`, and `service_logs_hint` points operators there instead of `journalctl`.

Set core size to zero before exec and run each process as `arkfile`. Never source `secrets.env` in a root shell: the file is owned by `arkfile`, so doing so would create a root command-injection path. Arkfile loads it internally via `ARKFILE_ENV_FILE`; rqlite and SeaweedFS use their existing command/config files and do not need to source it. Do not invent FreeBSD equivalents of every systemd sandbox knob in v1, but preserve security-critical controls that are portable: service identity, loopback binding, permissions, core suppression, and application-level memory protection.

### Wire service control through the adapter

Replace direct `systemctl` / `journalctl` call sites in:

- `scripts/dev-reset.sh`
- `scripts/setup/deploy-common.sh` (`stop_service_if_running`)
- `scripts/setup/deploy.sh` (unit install + enable)
- `scripts/setup/06-setup-rqlite-build.sh` (service install branch)
- `scripts/setup/05-setup-seaweedfs.sh` if it installs or enables a unit
- `scripts/setup/build.sh` (non-build-only service stop and service artifact staging)

`deploy.sh` becomes the single installer of service definitions. Stage `systemd/` and `rc.d/` into distinct build artifact directories in `build.sh`; deploy only the definition family selected by the service manager. On FreeBSD, skip Caddy definition installation and treat the existing dev-reset Caddy stop as an explicit no-op/absent service. Linux behavior must remain unchanged for existing systemd hosts.

### Users and directories

- `01-setup-users.sh`: FreeBSD branch using `pw`; keep Linux `groupadd`/`useradd`.
- `02-setup-directories.sh`: use `run_as_root` and portable random-file output; keep layout under `/opt/arkfile`.
- `04-setup-tls-certs.sh`: use shared privilege/service-user helpers, portable temporary files, and portable date handling.
- Ownership helpers: use resolved `ORIGINAL_USER` / `arkfile` consistently; avoid assuming `chown user:user` group name equals username if FreeBSD primary group differs (prefer explicit group from `id`).

### SeaweedFS on FreeBSD

In `05-setup-seaweedfs.sh`:

- Select asset from `BUILD_OS`/`BUILD_ARCH` (v1: `freebsd_amd64` only besides existing Linux).
- Pin a separate SHA-256 for the FreeBSD tarball (do not reuse the Linux digest).
- Use `sha256_file` shim instead of bare `sha256sum`.
- Keep install destination `/usr/local/bin/weed`.

### rqlite on FreeBSD

- Keep source build and existing `pkg` dependency install.
- Remove component-owned service-definition installation; `deploy.sh` owns it.
- Ensure the cached/already-current binary path does not skip required data-directory setup or adapter-driven service preparation.
- Do not require Linux-only static-extld flags on FreeBSD if the script already gates those to Linux; keep the FreeBSD build working and installable.
- Replace local `$SUDO_USER`/`sudo -u`/Go/git wrappers with the shared dev-user helpers.

### Build and link policy

- Bun: require native `pkg install bun`; fail with FreeBSD-oriented guidance.
- Emscripten: Linux retains pinned emsdk 3.1.74. FreeBSD selects native `emcc` from `pkg install emscripten`, rejects an unvalidated version, and never invokes emsdk installation. Validate the existing libsodium compatibility patch against the selected FreeBSD version.
- Server on Linux: retain the current fully static flags and verifier without weakening or broadening accepted dependencies.
- Server on FreeBSD: statically embed libopaque/liboprf/libsodium, permit evidenced FreeBSD base runtime libraries dynamically, and reject shared crypto or unexpected ports dependencies. Report build metadata accurately (do not emit unconditional `staticLinking: true`).
- CLI FIDO: continue vendored static crypto/FIDO archives plus evidenced OS runtime libraries. Extend verifier parsing for FreeBSD `ldd` output and its base libraries; reject unexpected `/usr/local/lib` dependencies.
- Replace GNU `stat -c`, `sha256sum`, and `sed -i` usages in `build.sh` / WASM build with portable helpers.
- Convert relevant shared-script shebangs from `/bin/bash` to `/usr/bin/env bash`; do not create a FreeBSD filesystem symlink.

### Go application/runtime portability

- Add explicit `ARKFILE_ENV_FILE` loading before `config.LoadConfig()`, using `godotenv.Load(path)` semantics so pre-existing environment variables keep precedence. Remove duplicate/default `.env` loading ambiguity or centralize it so configuration is loaded once in a clearly ordered path.
- Add `crypto/user_secret_master_freebsd.go` (and narrow the generic build tag) with native `mlock`, `munlock`, `MADV_NOCORE`, and process core-limit behavior.
- Add FreeBSD-targeted unit tests or compile tests for the platform functions. Warnings/no-ops used by unsupported platforms are not accepted as the FreeBSD implementation.
- Keep cryptographic behavior, password contexts, key derivation, streaming, and server-visible metadata unchanged.

### `dev-reset.sh` FreeBSD entry behavior

- Source `os-portable.sh` early.
- On FreeBSD: require root; resolve/validate dev user; reject major version below 15 and architecture other than amd64 before the NUKE confirmation.
- On Linux/systemd: preserve the current `sudo bash scripts/dev-reset.sh` invocation, argument parser, defaults, force-rebuild flags, systemd behavior, and fully static server build.
- Keep the same NUKE confirmation and step order.
- Replace ambiguous combined `pgrep`/`pkill` alternation with explicit portable process checks/kills while preserving Linux targets.
- Final status and log hints must be OS-aware.

### FreeBSD e2e portability

`scripts/testing/e2e-test.sh` is part of the implementation, not only an exit criterion:

- Replace `sha256sum` calls with the shared portable SHA-256 helper.
- Replace GNU-only file-size calls with `stat_size`.
- Add FreeBSD prerequisites (`jq`, `curl`, OpenSSL if not using base, and other evidenced commands).
- Make reset/deploy guidance OS-aware.
- Run e2e as the resolved non-root dev user, with that user's HOME/session files, after the root reset finishes.
- Do not change test semantics, privacy assertions, generated test sizes, or server API expectations.

### Host prerequisites (document in this WIP and later in setup docs)

Initial FreeBSD 15.1 amd64 package set (verify exact package names on the target host):

- `bash`, `git`, `go`, `gmake`, `cmake`, `pkgconf`, `perl5`, `python3`, `autoconf`, `automake`, `libtool`, `curl`, `ca_root_nss`, `jq`, `bun`, `emscripten`
- Bun and Go available in the resolved dev user's PATH
- Network access for FreeBSD packages, SeaweedFS release download, Go toolchain/modules if needed, and repository/vendor operations

Exact `pkg install ...` line should be updated here once validated on a real host.

### Devuan/non-systemd Linux follow-on

Do not add Devuan to this WIP's success claims. Design the adapter so a later Linux service-manager backend can be added independently:

- Linux package/OS behavior remains separate from service-manager behavior.
- Future SysVinit support would install `/etc/init.d` scripts and use `update-rc.d`/`service`.
- OpenRC and runit remain distinct future adapters, not aliases for SysVinit.
- A Linux host without systemd fails clearly until its manager is implemented.

After Linux/systemd and FreeBSD/rc.d both pass their blocking gates, Devuan/SysVinit is a small follow-on plan rather than an expansion of this first implementation.

### Documentation updates (with the implementation)

- `AGENTS.md`: note Linux as primary deploy host; FreeBSD `dev-reset` experimental; root + `ARKFILE_DEV_USER` on FreeBSD; agents still must not invoke deploy scripts themselves.
- `docs/setup.md`: replace aspirational "BSD supported" with accurate Linux-primary / FreeBSD-experimental wording and FreeBSD package notes for this path.
- When e2e is green, revise status in this file and soften "experimental" only to the extent proven (dev-reset + e2e-test, not prod-deploy).

## Non-goals during this initial project

- OpenBSD support
- FreeBSD aarch64
- FreeBSD releases below major version 15
- `local-deploy.sh` / `prod-deploy.sh` / `test-deploy.sh` / Caddy / deSEC on FreeBSD
- Playwright / `e2e-playwright.sh` on FreeBSD
- Official FreeBSD ports/packages packaging
- Requiring or depending on the `sudo` package on FreeBSD
- Allowing shared libopaque, liboprf, libsodium, libfido2, libcbor, libcrypto, or zlib from FreeBSD ports in Arkfile binaries
- Rewriting scripts from bash to POSIX sh
- Duplicating the entire setup tree under a `freebsd/` directory
- Claiming Devuan, SysVinit, OpenRC, or runit support before a separate backend is implemented and tested
- Replacing simple bootstrap shell operations with repeatedly compiled Go utilities

## Implementation Order

1. Record a clean Linux amd64 baseline using the developer-run `dev-reset.sh` then `e2e-test.sh`.
2. Add `os-portable.sh`: host/service-manager detection, FreeBSD 15+/amd64 preflight, root/dev-user resolution, argument-safe privilege helpers, service API, and portable tool helpers.
3. Route all independent `sudo`/`SUDO_USER` logic in the dev-reset call graph through the shared helpers; convert invoked Bash shebangs to `/usr/bin/env bash`.
4. Add Go `ARKFILE_ENV_FILE` loading and FreeBSD user-secret-master memory/core protection with tests.
5. Add `rc.d/{arkfile,rqlite,seaweedfs}` with systemd argument parity, service identity, pidfiles, file logging, loopback binds, and core suppression.
6. Stage both service-definition families in `build.sh`; make `deploy.sh` the sole definition installer; wire service stop/start/enable/status/log operations through the adapter.
7. Add FreeBSD `pw` user/group creation and portable directory/TLS/temp/random operations across `01` through `04`.
8. Add platform-keyed SeaweedFS download + independently pinned FreeBSD SHA-256; remove component-owned service installation.
9. Refactor rqlite Go/git/dev-user handling and cached path; remove component-owned service installation.
10. Add native FreeBSD Bun/Emscripten selection and portable WASM/build editing/checksum operations.
11. Implement OS-specific server/CLI link flags, verification, and accurate build metadata without changing Linux fully static behavior.
12. Port `e2e-test.sh` host utilities and guidance, preserving test semantics.
13. Run shell syntax and isolated adapter tests, then developer-run Linux `dev-reset.sh` + `e2e-test.sh`; resolve every Linux regression before FreeBSD validation.
14. Validate on FreeBSD 15.1-RELEASE amd64: root reset with `ARKFILE_DEV_USER`, then non-root e2e.
15. Repeat the complete Linux reset + e2e gate after FreeBSD passes.
16. Documentation honesty pass (`AGENTS.md`, `docs/setup.md`, this file's Status); only then consider a separate Devuan/SysVinit follow-on.

## Exit Criteria

### Shared implementation

- [ ] Host OS and service manager are detected independently; unsupported combinations fail before mutation
- [ ] `os-portable.sh` centralizes root/dev-user/service/tool behavior with no remaining conflicting `$SUDO_USER` implementations in the call graph
- [ ] Shared scripts use a Bash path valid on Linux and FreeBSD without filesystem symlinks
- [ ] Service definitions have one install owner (`deploy.sh`) and both artifact families are staged deterministically
- [ ] Arkfile loads an explicit env file internally without a root shell sourcing service-user-writable content
- [ ] Shell syntax checks pass for every modified shell script
- [ ] Isolated adapter tests verify Linux/systemd and FreeBSD/rc.d command selection without mutating host services

### Blocking Linux regression gate

- [ ] Existing invocation remains `sudo bash scripts/dev-reset.sh`; Linux requires no new flags/environment
- [ ] `--force-rebuild-all`, `--force-rebuild-rqlite`, `--help`, and unknown-option behavior remain unchanged
- [ ] Existing systemd service names, paths, start order, status behavior, units, and log guidance remain unchanged
- [ ] Linux server remains fully static and current CLI linking policy is not weakened
- [ ] Developer-run Linux amd64 `dev-reset.sh` completes and leaves all three services healthy
- [ ] Linux `scripts/testing/e2e-test.sh` passes
- [ ] Go tests pass with the CGO environment documented in `AGENTS.md`
- [ ] The complete Linux reset + e2e gate is repeated after FreeBSD passes

### Blocking FreeBSD gate

- [ ] Preflight accepts FreeBSD 15.1-RELEASE amd64 and rejects FreeBSD <15 / non-amd64
- [ ] Root + `ARKFILE_DEV_USER` resolution works without the sudo package; all builds/git operations run as the dev user
- [ ] Native `pkg` Bun and validated Emscripten build TypeScript and OPAQUE WASM successfully
- [ ] FreeBSD build embeds vendored crypto/FIDO archives and dynamically links only evidenced base-system runtime libraries
- [ ] FreeBSD user-secret-master uses native memory locking, no-core advice, and process core suppression
- [ ] rc.d scripts start, status, restart, and stop arkfile, rqlite, and seaweedfs reliably as `arkfile`
- [ ] rc.d services preserve loopback bindings, permissions, environment loading, pidfiles, and per-service logs
- [ ] SeaweedFS FreeBSD amd64 asset downloads and verifies against an independently pinned SHA-256
- [ ] `build.sh --build-only` succeeds as the resolved dev user (Bun + WASM included)
- [ ] Root `dev-reset.sh` completes and leaves all three services healthy
- [ ] Non-root `scripts/testing/e2e-test.sh` passes against that instance
- [ ] `AGENTS.md` and `docs/setup.md` describe Linux-primary / FreeBSD-experimental scope accurately

## Evidence to Record During Bring-Up

Record these in this document as they become known:

- Exact `pkg install` command validated on FreeBSD 15.1-RELEASE amd64
- Bun and Emscripten versions used for the successful build
- Pinned SHA-256 for SeaweedFS `freebsd_amd64.tar.gz` and the trusted acquisition procedure used to establish it
- `file` and `ldd` output for Arkfile server, client, and admin binaries, identifying every accepted FreeBSD base dependency
- rc.d/sysrc definitions, pidfile locations, log locations, and restart behavior
- Linux before/after reset + e2e results
- FreeBSD reset + e2e results

Any new dynamic ports dependency, shared crypto dependency, weakening of Linux static verification, root build fallback, root sourcing of `secrets.env`, or Linux dev-reset behavior change is a new locked decision requiring developer sign-off. It must not be treated as an implementation detail.
