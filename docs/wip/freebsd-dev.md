# FreeBSD Development Reset Path

## Reasoning

FreeBSD is a strong next host target for Arkfile’s development and self-hosted deploy path. It is a mature open-source Unix with a clear base-versus-ports split, first-class ZFS, and no dependency on systemd, which matches operators who want a small, auditable service model (`rc.d`) and storage that can add redundancy and resilience under a local SeaweedFS backend. Bringing `dev-reset` up there forces the deploy scripts to separate “run Arkfile” from “run on Linux systemd,” which is useful even for Linux, and it is a practical step before harder ports such as OpenBSD. The goal of this WIP is not a FreeBSD ports package or a production Caddy path; it is proving the same privacy-preserving stack can be built, reset, and e2e-tested on FreeBSD amd64 with shared scripts and thin OS adapters.

## Status

Draft planning document. Decisions in "Locked Decisions" and "Toolchain Decisions" are locked for the first FreeBSD bring-up; the three toolchain decisions (Emscripten version, FreeBSD server linking, Bun source) were signed off by the developer on 2026-10-08. No FreeBSD-specific deploy/runtime code has been written yet. The initial validation target is FreeBSD 15.1-RELEASE amd64; releases below FreeBSD 15 are unsupported.

The C/Go build layer already has partial FreeBSD awareness in `scripts/setup/build-config.sh` and related C-library scripts, and the CLI already has a FreeBSD agent implementation (`cmd/arkfile-client/agent_freebsd.go`) that has never run under e2e. The reset/deploy/runtime path, WASM toolchain, service management, privilege transitions, application memory hardening, SeaweedFS download, e2e script, and GNU/BSD userland seams all require work. A review of the current call graph against FreeBSD 15 base userland, the FreeBSD 15 package repositories, and upstream release artifacts found several hard failures and toolchain mismatches; they are listed in "Known Hard Failures in the Current Call Graph" and resolved in "Toolchain Decisions".

## Overview

Arkfile's development iteration loop today is Linux- and systemd-centric. `sudo bash scripts/dev-reset.sh` stops services, nukes data under `/opt/arkfile`, rebuilds (including vendored OPAQUE/FIDO C libraries and TypeScript), redeploys, regenerates secrets/keys, installs SeaweedFS and rqlite, and starts `seaweedfs` / `rqlite` / `arkfile` via `systemctl`. The Go application, client-side crypto, and most of `build.sh` are not inherently Linux-bound, but the reset/deploy/runtime scripts assume systemd, Linux `useradd`/`groupadd`, a group named `root`, GNU-only userland behavior (`stat -c`, `sed -i` without a suffix argument, `head -c -N`, GNU make as `make`), a `sudo` + `$SUDO_USER` privilege model, and a hardcoded SeaweedFS `linux_amd64` release asset.

The goal of this WIP is a FreeBSD amd64 path that reuses the same `dev-reset.sh` entrypoint and shared setup scripts, with thin OS adapters and FreeBSD `rc.d` service scripts. A standalone forked `freebsd-dev-reset.sh` is rejected because secrets generation, health checks, nuke steps, and build flags would drift from Linux. OpenBSD, Alpine/OpenRC, production Caddy deploy, and Playwright browser e2e are explicitly out of scope here.

Success for this WIP requires both platforms: the existing Linux amd64 `sudo bash scripts/dev-reset.sh` followed by `scripts/testing/e2e-test.sh` must remain green without a changed invocation or weakened linking/service behavior, and FreeBSD 15.1-RELEASE amd64 must complete the same reset and e2e workflow using root orchestration with a resolved non-root dev user for builds and tests. Linux remains the primary supported deploy host until both bars are green; docs should say so honestly.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Shape | Shared `scripts/dev-reset.sh` + OS adapters; no standalone FreeBSD fork of the full reset script |
| Adapter location | New `scripts/setup/os-portable.sh`, sourced by `dev-reset.sh`, `deploy-common.sh`, and setup scripts that need service/user/tool shims |
| Platform model | Detect host OS and service manager independently. Linux/systemd and FreeBSD/rc.d are implemented now; a non-systemd Linux host must fail clearly rather than being mistaken for FreeBSD. |
| Service model | New `rc.d/` tree parallel to `systemd/` for `arkfile`, `rqlite`, and `seaweedfs`, installed under `/usr/local/etc/rc.d` with the same process args and working directories as today's unit files |
| Service enablement | `sysrc arkfile_enable=YES`, `sysrc rqlite_enable=YES`, and `sysrc seaweedfs_enable=YES` |
| Service definition owner | `deploy.sh` installs all systemd or rc.d service definitions. SeaweedFS/rqlite setup scripts install binaries and data directories only; remove their duplicate service-definition installation paths. |
| Service supervision | `daemon(8)` with a supervisor pidfile (`-P`), a child pidfile (`-p`), restart (`-r`), output file (`-o`), and service user (`-u arkfile`). The rc.subr `pidfile` variable points at the supervisor pidfile so stop/status act on the supervisor, which forwards signals to the child. |
| Service working directory | `${name}_chdir` is mandatory. Arkfile serves `client/static/...` and other assets by relative path (`handlers/route_config.go`), so it must start in `/opt/arkfile` exactly as `WorkingDirectory=/opt/arkfile` does today. |
| Service logs | FreeBSD rc.d services log to per-service files under `/opt/arkfile/var/log` via `daemon -o`, owned by `arkfile` with mode 0640 or stricter, rotated by a `newsyslog.conf.d` entry that `deploy.sh` installs. Do not rely on syslog or journald for the development path. |
| Service safety | rc.d launchers run services as `arkfile`, bind rqlite/SeaweedFS to loopback exactly as today, and set the core limit to zero with rc.subr `${name}_limits="-c 0"` |
| Service environment | rc.d scripts must not use rc.subr `${name}_env_file`, which sources the file in the root rc shell. Arkfile receives only the non-secret `ARKFILE_ENV_FILE` path. rqlite and SeaweedFS receive no `secrets.env` content. |
| Install root | `/opt/arkfile` on FreeBSD as on Linux (path parity in secrets, units/rc scripts, and docs) |
| Binary install paths | `/usr/local/bin/weed`, `/usr/local/bin/rqlited`, `/usr/local/bin/rqlite` |
| Build root | `/var/tmp/arkfile-build` (already the shared default) |
| FreeBSD baseline | FreeBSD 15.1-RELEASE amd64 is the initial validation target. Reject FreeBSD major versions below 15 and non-amd64 FreeBSD hosts during preflight. Newer releases remain unvalidated until tested. |
| Privilege | FreeBSD path requires root (`EUID=0`). Do not require the `sudo` package. |
| Privileged execution | Add a shared `run_as_root` helper: execute directly when already root; retain existing sudo behavior for Linux scripts invoked by a non-root operator. Route every `sudo` in the dev-reset call graph through the helper instead of requiring sudo on FreeBSD. |
| Dev user for builds | Resolve non-root build/ownership user as `ARKFILE_DEV_USER`, else `$SUDO_USER` if set, else fail before mutation. Validate that it exists, is not root, is not `arkfile`, has a writable home, and can access the repository. Never run Go/bun/git builds as root. Do not add a `--dev-user` argument in v1. |
| Non-root execution | Add a shared argument-safe `run_as_dev_user`. Linux keeps current `sudo -u` semantics. FreeBSD root uses `env -i` with an explicit environment plus `/usr/sbin/chroot -u <user> -g <group> -G <groups> /` and an argument-array `exec` (see "Privilege Model"). Do not construct a shell command string from arguments. |
| Shell | Keep bash; FreeBSD hosts install `bash`, and every shared Bash script in the FreeBSD call graph uses `#!/usr/bin/env bash`. Do not require a `/bin/bash` symlink. |
| Users/groups | FreeBSD branch in `01-setup-users.sh` via `pw groupadd` / `pw useradd`, shell `/usr/sbin/nologin` |
| Root group | Never name a group called `root` in shared scripts. FreeBSD gid 0 is `wheel`. Use numeric gid `0` (`root:0`, `install -g 0`), which is valid on both Linux and FreeBSD. |
| SeaweedFS | Platform-keyed release asset (`freebsd_amd64.tar.gz`) and pinned SHA-256 digest map in `05-setup-seaweedfs.sh`. Upstream publishes only MD5 files, so the FreeBSD SHA-256 pin is established by our own download and recorded with its acquisition procedure. |
| rqlite | Keep build-from-source (`06-setup-rqlite-build.sh`); `deploy.sh` installs its selected service definition while the rqlite setup script owns only dependencies, source/build cache, binaries, and data directories |
| CLI linking | Extend CLI verification with an explicit FreeBSD base-library set (`libc`, `libthr`, and any other evidenced base dependency). libfido2 1.17 on FreeBSD uses the `hidraw(4)`/`uhid(4)` ioctl backend from kernel headers and needs no extra base library beyond threads. Reject unexpected ports libraries and keep vendored OPAQUE/FIDO/crypto archives static. |
| Go platform functions | Implement FreeBSD user-secret-master protection in build-tagged Go: `mlock`/`munlock`, `MADV_NOCORE` on a page-aligned buffer, `procctl(PROC_TRACE_CTL, PROC_TRACE_CTL_DISABLE)` as the counterpart of the anti-ptrace effect of Linux `PR_SET_DUMPABLE=0`, and process `RLIMIT_CORE=0`, with unit tests. Do not retain the generic non-Linux no-op for FreeBSD. |
| Arkfile env loading | Add explicit Go application support for `ARKFILE_ENV_FILE`. Parse it with the existing `godotenv` dependency before configuration loading, without overriding pre-existing process environment values. FreeBSD rc.d passes only the non-secret path. Never source `secrets.env` as root. Add a parsing parity test (see "Go application/runtime portability"). |
| Shell tool shims | FreeBSD 15 base already provides GNU-compatible `sha256sum` (via `md5(1)` links), `mktemp --tmpdir`, `find -executable`, `date +%N`, `base64`, and `grep` with GNU basic-regex extensions, so those call sites need no shim. Add portable helpers only where behavior differs: `stat_size` (`wc -c`), `stat_owner` (OS-specific `stat`), in-place file editing via temporary file and rename instead of `sed -i`, byte truncation instead of `head -c -N`, and explicit process matching instead of `\|` alternation in `pgrep`/`pkill`. Do not invoke `go run` for trivial host utilities. |
| GNU make for vendored WASM build | For the WASM step only, prepend a build-local directory to `PATH` in which `make` resolves to `gmake`. The upstream `libopaque/js/Makefile` is GNU make syntax and invokes sub-makes as a literal `make --directory=...`, so passing `gmake` at the top level is not sufficient. Do not edit vendored Makefiles. |
| Emscripten | Emscripten 6.0.3 on both platforms: emsdk 6.0.3 on Linux, `pkg install emscripten` 6.0.3 on FreeBSD. FreeBSD never attempts emsdk installation. See "Toolchain Decisions". |
| Server linking | Fully static Arkfile server on FreeBSD, as on Linux, verified by the existing `verify_server_binary_static`. See "Toolchain Decisions". |
| Bun | Official oven-sh `bun-v1.3.14` FreeBSD release binary, installed by the developer from a pinned, signature-verified zip. Not the FreeBSD `lang/bun` port and not `lang/bun-linux`. See "Toolchain Decisions". |
| FreeBSD package branch | FreeBSD dev hosts use the `latest` pkg repository, and `pkg lock` Emscripten and Go after validation. See "Toolchain Decisions". |
| TypeScript assets | Must be built on the FreeBSD host via bun; do not ship or reuse Linux-built `dist/` as a supported path |
| Preflight before NUKE | All host, privilege, dev-user, and toolchain checks run before the NUKE confirmation. A missing or wrong-version tool must not be discovered after data has been destroyed. |
| e2e portability | `scripts/testing/e2e-test.sh` is in scope for file-size, truncation, prerequisite, and reset-guidance portability. Run it as the non-root dev user after root finishes FreeBSD `dev-reset`. |
| Playwright | Out of scope for this WIP |
| local-deploy / prod-deploy / Caddy | Out of scope for this WIP |
| fdre2e.sh | Remains Linux-only in this WIP; it depends on `$SUDO_USER` via `testing_sudo_developer_or_die` |
| OpenBSD | Explicit non-goal; follow-on only after FreeBSD is green |
| Devuan / non-systemd Linux | Not an exit criterion for this WIP. Keep OS and service-manager detection separate so a later SysVinit/OpenRC/runit adapter can reuse this work without redesign. |
| Docs honesty | Until e2e is green: Linux is the supported deploy host; FreeBSD `dev-reset` is experimental/WIP. Update `AGENTS.md` and `docs/setup.md` accordingly when implementing and again when complete. |

## Toolchain Decisions

These three decisions were signed off by the developer on 2026-10-08. Facts below were checked on that date against the FreeBSD 15 amd64 `quarterly` and `latest` package catalogs, the FreeBSD ports tree, and upstream release artifacts.

### Emscripten 6.0.3 on both platforms

Linux currently pins emsdk Emscripten 4.0.23 (`EMSCRIPTEN_VERSION` in `build-config.sh`), and `ensure_emscripten` in `build-libopaque-wasm.sh` rejects any system `emcc` that does not match the pin exactly. emsdk publishes no FreeBSD host binaries. The FreeBSD `devel/emscripten` package is 6.0.3 in `latest` and 6.0.2 in `quarterly`, built against `llvm-devel`. emsdk has a 6.0.3 tag for Linux.

Decision: move `EMSCRIPTEN_VERSION` to 6.0.3 and prove it on Linux first as its own change (`dev-reset.sh`, `e2e-test.sh`, `e2e-playwright.sh`, and the OPAQUE WASM interop harness) before any FreeBSD work depends on it. FreeBSD then uses the `latest` package at 6.0.3 and runs `pkg lock emscripten` after validation. Keeping 4.0.23 on Linux next to 6.x on FreeBSD was rejected because it would mean two compatibility patch sets and two different `libopaque.js` artifacts from one commit, against the "one way to do things for a given client type" rule in `AGENTS.md`.

Known required change: Emscripten 6.0.0 flipped the `FAKE_DYLIBS` default from true to false, so `-shared` now produces a real dynamic library. The upstream libopaque.js Makefile builds `libopaque.so` with `emcc -shared` and then statically links `-L. -lopaque` into `libopaque.js`, which relies on the old behavior. `-sFAKE_DYLIBS=1` is passed on both the `libopaque.so` and `libopaque.js` link steps in `build-libopaque-wasm.sh` (the setting still exists in 6.0.3) rather than editing the vendored Makefile. The pinned libsodium.js 0.8.4 `emscripten.sh` still passes `-s NODEJS_CATCH_EXIT=0` and `-s NODEJS_CATCH_REJECTION=0`, both removed in 5.0.2; 6.0.3 lists them as legacy settings whose value `0` is accepted with a warning (`tools/settings.py`), so no patch is needed, but the build log will show legacy-setting warnings.

Linux change status: implemented 2026-10-09, pending the Linux validation gate. The change set is: `EMSCRIPTEN_VERSION=6.0.3` in `build-config.sh`; `-sFAKE_DYLIBS=1` on both WASM link steps; the emsdk checkout pinned to the emsdk tag matching `EMSCRIPTEN_VERSION` (previously an unpinned clone whose `git fetch --all` never updated the working tree, so an older checkout's release list might not include the pinned version); and a WASM build stamp (`libopaque_wasm_build_stamp` / `libopaque_wasm_cache_valid` in `build-config.sh`, written by `build-libopaque-wasm.sh`) so non-production builds that skip C libraries rebuild WASM whenever the Emscripten version, sources, trace defines, or WASM build script change. Validation: rebuild WASM, run `go test -v ./auth -run TestOpaqueNativeServerWASMClientInterop` (confirm it ran rather than skipped), `e2e-test.sh`, `e2e-playwright.sh`, then `test-update.sh` on the test VPS with browser logins by accounts registered under 4.0.23 before `prod-update.sh`.

Unchanged between 4.0.23 and 6.0.3: the generated-code browser minimums (`MIN_FIREFOX_VERSION` 79, `MIN_CHROME_VERSION` 85, `MIN_SAFARI_VERSION` 15.0), so no supported browser, including Tor Browser and older mobile browsers, loses support. `MIN_NODE_VERSION` rose from 16.0 to 18.3, which does not affect Arkfile because Bun runs the WASM harness.

Limitation: the FreeBSD package is built against an `llvm-devel` snapshot rather than the LLVM that emsdk bundles, so Linux and FreeBSD builds will not be byte-identical even at the same Emscripten version. The cross-platform gate is behavioral: the interop harness passes on both builds, and a user registered through one platform's build logs in through the other's. When the FreeBSD package version changes, the pin is revalidated deliberately on Linux first.

### Fully static server on FreeBSD

`verify_server_binary_static` already requires a statically linked server on FreeBSD, FreeBSD base ships static `libc` and `libthr`, and static linking on FreeBSD avoids the glibc resolver caveats. Decision: keep the existing `-extldflags "-static"` path on FreeBSD. If the static link reports libc resolver or user-lookup problems, add `-tags netgo,osusergo` for FreeBSD only. Dynamic base libraries are permitted only if a static link is shown to fail, with the error, the `ldd` output, and the accepted library list recorded here and signed off. On pkgbase installs, the base development packages that provide headers and static archives are a documented prerequisite. rqlite, a third-party service binary, may link dynamically against base libraries; record its `ldd` output.

### Bun: pinned upstream `bun-v1.3.14` FreeBSD release binary

Neither FreeBSD 15 package repository has a native `bun` package: `lang/bun` is marked `BROKEN= Checksum error`. `latest` carries `lang/bun-linux` 1.3.14, which runs the Linux binary under the Linux compatibility layer. Neither is used. oven-sh publishes official native FreeBSD binaries starting with `bun-v1.3.14`, the exact Zig-built version Arkfile pins (`BUN_ZIG_VERSION`), signed with the same release process as the Linux binaries. 1.3.13 and earlier have no FreeBSD assets. This gives FreeBSD the same upstream release, at the same version, that Linux developers run, with no Linux compatibility layer and no dependence on the broken port.

Pinned artifact (verified 2026-10-08):

| Item | Value |
|------|-------|
| Release | `bun-v1.3.14` (published 2026-05-13) |
| Zip | `https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-freebsd-x64.zip` |
| Zip SHA-256 | `b881dc4ddbd68c79a35bd3549088bd1d7003b562cec3cb7954c0ca8b6f5288a5` |
| Binary inside zip | `bun-freebsd-x64/bun` (ELF 64-bit x86-64, FreeBSD) |
| Binary SHA-256 | `72aa72cad645cddb83601eb34105a72f3d76d332ec3aa5a469a5a6f0ca845793` |
| Checksum source | `SHASUMS256.txt`, clearsigned as `SHASUMS256.txt.asc` in the same release |
| Signing key | "Robobun <robobun@oven.sh>", EdDSA, fingerprint `F3DC C08A 8572 C074 9B3E 1888 8EAB 4D40 A7B2 2B59`, fetched from keys.openpgp.org |

The `bun-freebsd-x64-baseline.zip` (zip SHA-256 `cf24aff5d2b7d7c1d9838f58ae6162a5565e87584495fb8bcd2cfbae4f645d92`) contains a byte-identical `bun` binary, so one binary pin covers both and the CPU-baseline choice does not arise for 1.3.14 on FreeBSD. The `-profile` zips are debug builds and are not used. This is upstream's first FreeBSD release, so its behavior must be validated on the host (see "Exit Criteria").

Establishing or refreshing the pin (developer, once per Bun version, on any host with `gpg`):

```bash
B=https://github.com/oven-sh/bun/releases/download/bun-v1.3.14
curl -fsSLO "$B/SHASUMS256.txt.asc" && curl -fsSLO "$B/bun-freebsd-x64.zip"
gpg --recv-keys F3DCC08A8572C0749B3E18888EAB4D40A7B22B59   # or import from keys.openpgp.org
gpg --verify SHASUMS256.txt.asc                            # must report a good signature from that fingerprint
gpg --decrypt SHASUMS256.txt.asc 2>/dev/null | grep ' bun-freebsd-x64.zip$'
sha256sum bun-freebsd-x64.zip                              # must equal the signed line
unzip -p bun-freebsd-x64.zip bun-freebsd-x64/bun | sha256sum   # binary pin
```

The two digests are recorded in `build-config.sh` next to `BUN_ZIG_VERSION` as `BUN_FREEBSD_X64_ZIP_SHA256` and `BUN_FREEBSD_X64_BIN_SHA256`. Scripts never run `gpg`; the signature check is a pin-establishment step, and the scripts trust the recorded digests.

Installing on a FreeBSD dev host (developer, as the dev user, matching the Linux rule that `dev-reset.sh` does not install Bun). `bun.sh/install` has no FreeBSD support, so the install is manual:

```sh
fetch https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-freebsd-x64.zip
sha256sum bun-freebsd-x64.zip      # must equal BUN_FREEBSD_X64_ZIP_SHA256
unzip -q bun-freebsd-x64.zip
install -d -m 755 ~/.bun/bin
install -m 755 bun-freebsd-x64/bun ~/.bun/bin/bun
~/.bun/bin/bun --version           # 1.3.14
```

`~/.bun/bin/bun` is the same location the Linux installer uses, and `find_bun_binary` already searches it. Do not install `lang/bun-linux` alongside it: that package installs a conflicting `/usr/local/bin/bun` wrapper that `find_bun_binary` would find first via `PATH`.

Script support (implementation):

- `build-config.sh`: add `BUN_FREEBSD_X64_ZIP_SHA256` and `BUN_FREEBSD_X64_BIN_SHA256`; give `print_bun_install_hint` a FreeBSD branch that prints the install procedure above with the pinned digest instead of the `bun.sh/install` command.
- `find_bun_binary`: resolve the dev user's home through the adapter's `ORIGINAL_USER`, not `$SUDO_USER`, so a FreeBSD root shell with `ARKFILE_DEV_USER` finds `~dev/.bun/bin/bun`.
- `check_dev_reset_toolchain` (FreeBSD branch, before NUKE): require Bun 1.3.x through `require_bun_zig_build`, and require `sha256sum` of the resolved Bun binary to equal `BUN_FREEBSD_X64_BIN_SHA256`. A mismatch is a hard failure with the install hint. Linux Bun checks are unchanged.

### FreeBSD package branch: `latest`

FreeBSD dev hosts use the `latest` pkg repository. Reasons, from the 2026-10-08 catalogs: `latest` has Emscripten 6.0.3 (quarterly has 6.0.2), and in `quarterly` the `go` metaport is still Go 1.25, which is too old for `go 1.26.6` in `go.mod` (the separate `go126` package is 1.26.7 there, but `find_go_binary` would pick the older `go` first if both are installed). `latest` has the `go` metaport at 1.26. After validation, `pkg lock emscripten go` (and the concrete `go126` package it depends on) so routine upgrades cannot change the pinned toolchain; record locked versions under "Evidence". A host that must use `quarterly` installs `go126` explicitly, puts `/usr/local/go126/bin` first in the dev user's `PATH`, and still needs Emscripten 6.0.3, which may not be available there yet.

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

Without this work, today's `run_as_user` in `deploy-common.sh` silently runs the build as root when `$SUDO_USER` is unset, which is exactly the FreeBSD root-shell case. The adapter must close that path rather than fall through to it.

The FreeBSD `run_as_dev_user` shape is an argument array passed through a fixed shell snippet, never a command string built from arguments:

```bash
env -i \
    HOME="$DEV_HOME" USER="$DEV_USER" LOGNAME="$DEV_USER" \
    PATH="$DEV_PATH" SHELL=/bin/sh \
    ${EMSDK_PYTHON:+EMSDK_PYTHON="$EMSDK_PYTHON"} \
    /usr/sbin/chroot -u "$DEV_USER" -g "$DEV_GROUP" -G "$DEV_GROUPS" / \
    /bin/sh -c 'cd "$1" && shift && exec "$@"' arkfile-dev "$PWD" "$@"
```

The selected environment passthrough list (for example `VERSION`, `GIT_COMMIT`, `SKIP_C_LIBS`, `GOTOOLCHAIN`, `LIBOPAQUE_DEFINES`, `ARKFILE_ALLOW_WASM_TRACE`) is defined once in the adapter and shared with the Linux `sudo -u ... env` path. Validate the helper on the target host with arguments containing spaces, quotes, and glob characters before routing builds through it.

## Current Call Graph (Linux baseline)

```
scripts/dev-reset.sh
├── scripts/setup/build-config.sh
├── scripts/setup/deploy-common.sh
├── stop services (systemctl) + pkill
├── nuke /opt/arkfile data + /tmp/arkfile-e2e-test-data
├── run_as_user ./scripts/setup/build.sh --build-only
│   ├── ./scripts/setup/ensure-vendor-c.sh
│   ├── ./scripts/setup/build-libopaque.sh        # native libsodium/liboprf/libopaque (gmake-aware)
│   ├── ./scripts/setup/build-libopaque-wasm.sh   # emsdk, bare make, sed -i, npm/npx via upstream Makefile
│   ├── bun install / type-check / build:prod
│   ├── ./scripts/setup/build-libfido2.sh         # zlib, OpenSSL libcrypto, libcbor, libfido2 (CLI only)
│   ├── go build server + CLIs, linking verification
│   └── SRI injection (sed -i), stage systemd/ and database/
├── ./scripts/setup/01-setup-users.sh
├── ./scripts/setup/02-setup-directories.sh
├── ./scripts/setup/deploy.sh          # copies build root, chown root:root bin, installs systemd units
├── secrets / seaweedfs-s3.json / rqlite-auth.json
├── ./scripts/setup/03-setup-master-key.sh
├── ./scripts/setup/04-setup-tls-certs.sh
├── ./scripts/setup/05-setup-seaweedfs.sh   # linux_amd64 tarball today, installs unit
├── ./scripts/setup/06-setup-rqlite-build.sh  # installs unit
└── systemctl start/enable seaweedfs, rqlite, arkfile + health checks
```

FreeBSD keeps this step order. OS-specific behavior is restricted to explicit host/service-manager branches. Linux defaults, systemd commands, service order, paths, current argument parsing, and fully static server behavior must not change.

## What Already Helps

`build-config.sh` already normalizes `FreeBSD` into `BUILD_OS=freebsd`, prefers `gmake`, can use `sysctl hw.ncpu`, maps OpenSSL Configure targets for FreeBSD, and prints FreeBSD package hints. `build-libopaque.sh` / `build-libfido2.sh` already treat FreeBSD as a supported C build OS and select `gmake` through `find_make_command`. `verify_server_binary_static` already has a FreeBSD branch that requires a statically linked server. `06-setup-rqlite-build.sh` already has a `pkg` dependency branch and soft-fails systemd install with a manual rc.d note. `cmd/arkfile-client/agent_freebsd.go` already implements `mlock` and `LOCAL_PEERCRED` peer checks for the CLI agent socket. SeaweedFS 4.18 publishes a `freebsd_amd64.tar.gz` artifact. FreeBSD 15 base provides `sha256sum`, `mktemp --tmpdir`, `find -executable`, `date +%N`, and `base64`, which removes several expected shims. oven-sh publishes an official native FreeBSD binary for the pinned Bun 1.3.14, and the FreeBSD `latest` repository carries Emscripten 6.0.3 and Go 1.26 (see "Toolchain Decisions"). These pieces are starting points, not a complete FreeBSD reset path.

## Known Hard Failures in the Current Call Graph

These were found by reading the current scripts against FreeBSD 15 base userland. Each one stops or silently corrupts a FreeBSD run and must be fixed (with Linux behavior unchanged) before bring-up.

- `scripts/setup/deploy.sh`: `chown -R root:root ${BASE_DIR}/bin` fails because FreeBSD has no `root` group, and `set -e` aborts the deploy. Use `root:0`. The same pattern appears as `install -o root -g root` in the non-build-only path of `build.sh` and in the Caddy helpers and rollback in `deploy-common.sh` (out of scope here, same fix).
- `scripts/setup/build.sh` (`inject_sri_attributes`): `sed -i -e ... -e ...` on FreeBSD consumes the first `-e` as the backup suffix and then treats the next expression as a file, so SRI injection fails. Replace with the shared in-place edit helper.
- `scripts/setup/build-libopaque-wasm.sh` (`patch_emscripten_for_modern_emcc`): `sed -i` without a suffix, and `sed -i '1s/^/...\n/'` relies on GNU `\n` in the replacement. Replace with the shared in-place edit helper.
- `scripts/setup/build-libopaque-wasm.sh` (`build_wasm_library`): bare `make` invocations, and the upstream `libopaque/js/Makefile` uses GNU make syntax (`$(shell ...)`, `ifeq`, `:=`) and literal `make --directory=...` sub-makes for libsodium.js and liboprf. Requires the GNU make `PATH` shim.
- `scripts/setup/build-libopaque-wasm.sh` via the upstream Makefile: the `node_modules` target runs `npm install` and `dist/libopaque.js` runs `npx terser`. On Linux, `node`/`npm`/`npx` come from the emsdk-bundled Node. The FreeBSD `devel/emscripten` port pulls in Node but not npm, so `www/npm` is a FreeBSD prerequisite. This is an upstream Makefile requirement, not a project choice of npm over bun.
- `scripts/setup/build.sh` (`fix_vendor_ownership`): `stat -c '%U'` does not exist on FreeBSD (`stat -f '%Su'`). Use `stat_owner`.
- `scripts/dev-reset.sh`: `pgrep -f "arkfile\|weed\|rqlited"` and the matching `pkill -9`. FreeBSD `pgrep`/`pkill` compile patterns with libc extended regex without GNU extensions, so `\|` is not alternation and the force-kill branch silently never fires. Use separate patterns.
- `scripts/setup/01-setup-users.sh`: `groupadd`/`useradd` and `/sbin/nologin` (FreeBSD: `pw` and `/usr/sbin/nologin`).
- `scripts/setup/05-setup-seaweedfs.sh`: hardcoded `linux_amd64` asset and Linux digest; installs a systemd unit and runs `systemctl daemon-reload`.
- `scripts/setup/06-setup-rqlite-build.sh`: unconditional `sudo`, its own `$SUDO_USER` handling, a `bash -c` string built around `$(pwd)` in `run_go_as_user`, and an early `exit 0` on the cached-binary path that installs a systemd unit and skips the rest of service preparation.
- `scripts/setup/build-config.sh` (`verify_cli_binary_linking`): parses Linux `ldd` output. FreeBSD `ldd` prints a `path:` header line first, which the parser would reject as an unexpected library.
- `scripts/setup/build-config.sh` (`missing_native_build_host_deps`) and `build-libopaque.sh` hints: require or recommend `gcc`. FreeBSD uses base `cc` (clang); `gcc` must not be required or suggested on FreeBSD.
- `scripts/testing/e2e-test.sh`: `head -c -16` (truncated-bundle test) is rejected by FreeBSD `head`. `stat -c%s ... || echo 0` in the export/decrypt size checks silently yields 0 instead of failing. Use the truncation and `stat_size` helpers.
- `cmd/arkfile-client/main.go` (`agent status` orphan audit): scans `/proc` for orphaned `__agent-daemon` processes. FreeBSD does not mount procfs by default, so the audit always reports "no daemon process detected", a false negative on a check whose purpose is finding key material left in memory. Use `sysctl kern.proc` (via `golang.org/x/sys/unix`) on FreeBSD and fail loudly if enumeration is unavailable.
- `crypto/user_secret_master_other.go`: the `!linux` build tag gives FreeBSD the no-op/err implementation for core-dump suppression, `mlock`, and `madvise`.

Verified non-issues on FreeBSD 15 base: `sha256sum` (GNU-compatible names via `md5(1)`), `mktemp --tmpdir=/tmp` in `04-setup-tls-certs.sh`, `find -type f -executable` in `deploy.sh`, `date +%s%N` in `e2e-test.sh`, `base64`, `seq`, and GNU basic-regex extensions such as `\+` in `grep` (base `grep` links libregex). `date -d` in `04-setup-tls-certs.sh` already has an `N/A` fallback and is harmless.

## Implementation Outline

### `scripts/setup/os-portable.sh`

Add a small shared adapter. Keep host OS and service-manager detection separate. Responsibilities:

- Detect OS via existing `detect_build_platform` / `uname` (reuse `BUILD_OS` from `build-config.sh` where already sourced).
- Detect service manager independently: `systemd` on the existing Linux path and `freebsd-rc` on FreeBSD. An unsupported Linux manager receives a precise error, not a FreeBSD branch.
- Resolve `ARKFILE_DEV_USER` / `$SUDO_USER` into one validated `ORIGINAL_USER`, uid, primary group name, gid, supplementary groups, and home for ownership and non-root execution.
- On FreeBSD: require `EUID=0`, FreeBSD major 15 or newer, amd64, and a resolved non-root dev user; error before mutation otherwise.
- `run_as_root`: direct exec when root; preserve current Linux sudo behavior when a setup script is intentionally run as non-root.
- `run_as_dev_user`: argument-safe privilege drop with the correct home, working directory, and selected environment, as described in "Privilege Model".
- `check_dev_reset_toolchain`: FreeBSD branch checks `bash`, `git`, `go` (meeting `go.mod`), `gmake`, `cmake`, `pkgconf`, `perl` plus the OpenSSL Configure modules, `python3` (3.10+), autotools including `libtoolize`, `curl`, `jq`, `openssl`, `unzip`, `npm`, Bun 1.3.x whose binary SHA-256 equals `BUN_FREEBSD_X64_BIN_SHA256`, `emcc` 6.0.3, and `wasm-opt`. Linux keeps its current checks. Called by `dev-reset.sh` before the NUKE confirmation.
- Service API used by reset/deploy: `service_stop`, `service_start`, `service_enable`, `service_is_active`, `service_install_definition`, `service_daemon_reload`, and `service_logs_hint`.
- Tool helpers: `stat_size`, `stat_owner`, `edit_in_place` (temporary file in the same directory, then rename, preserving mode), `truncate_tail_bytes`, and explicit per-name process matching.
- `make_gnu_shim_dir`: create a build-local directory under `$BUILD_ROOT` containing `make` pointing at `gmake`, for use only around the vendored WASM build.
- Reject unsupported OS/service-manager combinations early.

Route all privilege and dev-user logic in the call graph through these helpers. This includes `deploy-common.sh`, `build-config.sh` (`fix_go_ownership`, `run_go_as_user`, `ensure_build_dir`, `find_bun_binary`), `dev-reset.sh`'s local ownership helper, `build.sh`, `build-libopaque-wasm.sh`, `01` through `06` setup scripts, and `deploy.sh`. Do not leave independent `$SUDO_USER` interpretations in component scripts. Ownership helpers use the resolved primary group, not `user:user`, because a FreeBSD primary group need not match the username.

### FreeBSD `rc.d` scripts

Add `rc.d/arkfile`, `rc.d/rqlite`, `rc.d/seaweedfs` with the same executable paths, bind addresses, config files, and working directories as `systemd/*.service` today:

- arkfile: `/opt/arkfile/bin/arkfile`, `arkfile_chdir=/opt/arkfile`, non-secret `ARKFILE_ENV_FILE=/opt/arkfile/etc/secrets.env`, user/group `arkfile`
- rqlite: `/usr/local/bin/rqlited` with the existing localhost raft/http args and auth file, `rqlite_chdir=/opt/arkfile/var/lib/database`
- seaweedfs: `/usr/local/bin/weed server` with the existing localhost S3/master/volume/filer ports and config path, `seaweedfs_chdir=/opt/arkfile/var/lib/seaweedfs`

Each script uses rc.subr with `command=/usr/sbin/daemon`, `command_args` of the form `-P <supervisor.pid> -p <child.pid> -r -R 5 -o /opt/arkfile/var/log/<name>.log -u arkfile <program> <args>`, `pidfile` set to the supervisor pidfile, `${name}_limits="-c 0"`, and rcorder headers (`PROVIDE`, `REQUIRE: NETWORKING`, plus `REQUIRE: rqlite seaweedfs` for arkfile, `KEYWORD: shutdown`). Confirm on the host where `daemon(8)` writes pidfiles relative to its privilege drop and choose a pidfile directory (`/var/run` or `/opt/arkfile/var/run`) accordingly. Install into `/usr/local/etc/rc.d/` and enable with explicit `sysrc <service>_enable=YES`. `service_logs_hint` points operators at the log files instead of `journalctl`.

Never source `secrets.env` in a root shell: the file is owned by `arkfile`, so doing so would create a root command-injection path. This rules out rc.subr `${name}_env_file`. Arkfile loads the file internally via `ARKFILE_ENV_FILE`; rqlite and SeaweedFS use their existing command/config files and do not need it. Do not invent FreeBSD equivalents of every systemd sandbox knob in v1, but preserve the security-critical controls in "Security Parity" below.

`deploy.sh` also installs `/usr/local/etc/newsyslog.conf.d/arkfile.conf` rotating the three log files as `arkfile:arkfile` mode 640, with the rotation signal or `daemon(8)` log reopen behavior verified on the host.

### Wire service control through the adapter

Replace direct `systemctl` / `journalctl` call sites in:

- `scripts/dev-reset.sh`
- `scripts/setup/deploy-common.sh` (`stop_service_if_running`)
- `scripts/setup/deploy.sh` (unit install + enable)
- `scripts/setup/06-setup-rqlite-build.sh` (service install branch and cached-binary early exit)
- `scripts/setup/05-setup-seaweedfs.sh` (unit install and `daemon-reload`)
- `scripts/setup/build.sh` (non-build-only service stop and service artifact staging)

`deploy.sh` becomes the single installer of service definitions. Stage `systemd/` and `rc.d/` into distinct build artifact directories in `build.sh` (add a `BUILD_RCD` variable next to `BUILD_SYSTEMD` in `build-config.sh`); deploy only the definition family selected by the service manager. Every place that cleans `BUILD_SYSTEMD` must also clean `BUILD_RCD`: the selective clean in `dev-reset.sh`, `wipe_build_artifacts_preserving_c_libs_if_skipping` in `deploy-common.sh`, `clean_build_dir`, and `ensure_build_dir`. On FreeBSD, skip Caddy definition installation and treat the existing dev-reset Caddy stop as an explicit no-op/absent service. Linux behavior must remain unchanged for existing systemd hosts. The update-path rollback logic in `deploy-common.sh` is systemd-only and stays out of scope with the update scripts.

### Users and directories

- `01-setup-users.sh`: FreeBSD branch using `pw`; keep Linux `groupadd`/`useradd`.
- `02-setup-directories.sh`: use `run_as_root`; keep layout under `/opt/arkfile`. `dd ... status=none` is supported by FreeBSD `dd`.
- `04-setup-tls-certs.sh`: use shared privilege/service-user helpers in place of `sudo -u arkfile`. `mktemp --tmpdir` works on FreeBSD 15.
- `deploy.sh` and `build.sh`: replace every `root:root` and `-g root` with numeric gid `0`.

### SeaweedFS on FreeBSD

In `05-setup-seaweedfs.sh`:

- Select asset from `BUILD_OS`/`BUILD_ARCH` (v1: `freebsd_amd64` only besides existing Linux).
- Pin a separate SHA-256 for the FreeBSD tarball (do not reuse the Linux digest); cache under a platform-keyed tarball name.
- Keep `sha256sum`; it exists on both platforms.
- Keep install destination `/usr/local/bin/weed`.
- Remove unit installation and `daemon-reload`; `deploy.sh` owns service definitions.

### rqlite on FreeBSD

- Keep source build and existing `pkg` dependency install, routed through `run_as_root`.
- Remove component-owned service-definition installation; `deploy.sh` owns it.
- Ensure the cached/already-current binary path does not skip required data-directory setup or adapter-driven service preparation.
- Keep the existing Linux-only static-extld gating; the FreeBSD rqlite build links dynamically against base libraries, which is acceptable for a third-party service binary and is recorded under "Evidence".
- Replace local `$SUDO_USER`/`sudo -u`/Go/git wrappers and the `bash -c` command string with the shared dev-user helpers.

### Build and link policy

- Bun: the pinned upstream FreeBSD binary from "Toolchain Decisions"; `require_bun_zig_build` continues to enforce 1.3.x on both platforms, and the FreeBSD preflight additionally checks the binary digest.
- Emscripten: 6.0.3 on both platforms. The Linux pin move (including `-sFAKE_DYLIBS=1` in `WASM_LIBOPAQUE_LDFLAGS`) lands and passes the Linux gate first. FreeBSD selects native `emcc`, rejects any version other than `EMSCRIPTEN_VERSION`, and never invokes emsdk installation. Revalidate the libsodium.js `emscripten.sh` compatibility patch against 6.0.3.
- WASM build on FreeBSD: run the vendored Makefile targets with the GNU make shim directory first in `PATH`, require `npm`/`npx` from `www/npm`, and keep `validate_wasm_runtime` mandatory.
- Server on Linux: retain the current fully static flags and verifier without weakening or broadening accepted dependencies.
- Server on FreeBSD: fully static with the existing verifier; `-tags netgo,osusergo` only if the FreeBSD static link requires it. `version.json` keeps `staticLinking: true` only while every platform build is verified static.
- CLI FIDO: continue vendored static crypto/FIDO archives plus evidenced OS runtime libraries. Extend verifier parsing for FreeBSD `ldd` output (skip the `path:` header) and its base libraries; reject unexpected `/usr/local/lib` dependencies.
- Replace GNU `stat -c` and `sed -i` usages in `build.sh` / WASM build with the shared helpers.
- Convert relevant shared-script shebangs from `/bin/bash` to `/usr/bin/env bash`; do not create a FreeBSD filesystem symlink.

### Go application/runtime portability

- Add explicit `ARKFILE_ENV_FILE` loading before `config.LoadConfig()`, using `godotenv.Load(path)` semantics so pre-existing environment variables keep precedence. Today both `main.go` and `config.LoadConfig()` call `godotenv.Load()` for a default `.env`; centralize this so configuration is loaded once in a clearly ordered path.
- Add a parsing parity test for `ARKFILE_ENV_FILE`. `godotenv` expands `$VAR`/`${VAR}`, strips inline `#` comments, and handles quotes, which differs from systemd `EnvironmentFile`. The test covers values containing `$`, `#`, quotes, and `=` so a secret is never silently altered.
- Add `crypto/user_secret_master_freebsd.go` and narrow the generic build tag to `!linux && !freebsd`. Implement `mlock`/`munlock`, `MADV_NOCORE`, `setrlimit(RLIMIT_CORE, 0)`, and `procctl(P_PID, getpid, PROC_TRACE_CTL, PROC_TRACE_CTL_DISABLE)`. The vendored `golang.org/x/sys/unix` exposes `SYS_PROCCTL` but no `procctl` wrapper, so this is a raw syscall with a unit test that reads the state back with `PROC_TRACE_STATUS`.
- Linux already holds the user-secret master in a dedicated anonymous page (see "Linux Issues Surfaced by This Review"). The FreeBSD file provides its own `allocSecretPage`/`freeSecretPage` with `unix.Mmap` so `mlock` and `MADV_NOCORE` apply to a page containing only the key.
- Replace the CLI `agent status` `/proc` scan with a FreeBSD `kern.proc` implementation behind a build tag, keeping the Linux `/proc` path, and report an explicit error when process enumeration is unavailable instead of "no daemon process detected".
- Add FreeBSD unit tests for the platform functions and run `go test ./...` on the FreeBSD host with the CGO environment from `AGENTS.md`. Warnings/no-ops used by unsupported platforms are not accepted as the FreeBSD implementation.
- Keep cryptographic behavior, password contexts, key derivation, streaming, and server-visible metadata unchanged.

### `dev-reset.sh` FreeBSD entry behavior

- Source `os-portable.sh` early.
- On FreeBSD: require root; resolve/validate dev user; reject major version below 15 and architecture other than amd64; run `check_dev_reset_toolchain`. All of this happens before the NUKE confirmation.
- On Linux/systemd: preserve the current `sudo bash scripts/dev-reset.sh` invocation, argument parser, defaults, force-rebuild flags, systemd behavior, and fully static server build.
- Keep the same NUKE confirmation and step order.
- Replace the combined `pgrep`/`pkill` alternation with explicit per-name process checks/kills while preserving Linux targets.
- Final status and log hints must be OS-aware.

### FreeBSD e2e portability

`scripts/testing/e2e-test.sh` is part of the implementation, not only an exit criterion:

- Replace GNU-only file-size calls with `stat_size`, and make size checks fail rather than fall back to 0.
- Replace `head -c -16` with the byte truncation helper.
- Add FreeBSD prerequisites (`jq`, `curl`, `openssl`, and other evidenced commands); `sha256sum` needs no change.
- Make reset/deploy guidance OS-aware.
- Run e2e as the resolved non-root dev user, with that user's HOME/session files, after the root reset finishes. This is the first exercise of `agent_freebsd.go`; check that the dev user's login class `memorylocked` limit allows the agent's `mlock` calls.
- Do not change test semantics, privacy assertions, generated test sizes, or server API expectations.

### Adapter tests

Add a developer-run, non-root test script under `scripts/testing/` that sources `os-portable.sh` with `PATH` shims under `/tmp/arkfile-*` stubbing `uname`, `systemctl`, `service`, `sysrc`, `pw`, `useradd`, and `stat`. It asserts which commands each adapter function would run for Linux/systemd and FreeBSD/rc.d, and that unsupported combinations fail. It follows the test identity rule in `AGENTS.md`: refuses root and writes only under `/tmp/arkfile-*`.

### Security Parity

| Linux control today | FreeBSD mechanism | Proof |
|---------------------|-------------------|-------|
| `User=arkfile` / `Group=arkfile` | `daemon -u arkfile` | `ps -o user` on each service child |
| `LimitCORE=0` | rc.subr `${name}_limits="-c 0"` plus Go `setrlimit` | `procstat -l` on the child |
| `PR_SET_DUMPABLE=0` (no core, no same-uid ptrace) | `procctl` `PROC_TRACE_CTL_DISABLE` plus core limit | Unit test via `PROC_TRACE_STATUS`; attach attempt as `arkfile` fails |
| `mlock` of user-secret master | `unix.Mlock` on page-aligned buffer | Unit test; startup log has no mlock warning |
| `MADV_DONTDUMP` | `MADV_NOCORE` on page-aligned buffer | Unit test |
| Loopback-only rqlite/SeaweedFS | Same command args | `sockstat -4 -6 -l` shows only 127.0.0.1 |
| `EnvironmentFile` read by systemd as root, not by a shell | `ARKFILE_ENV_FILE` read by Arkfile as `arkfile`; no `${name}_env_file` | rc scripts reviewed; parser parity test |
| CLI agent `SO_PEERCRED` | `LOCAL_PEERCRED` via `GetsockoptXucred` (exists) | e2e agent tests on FreeBSD |
| `ProtectSystem`, `PrivateTmp`, `PrivateDevices`, `SystemCallFilter`, `NoNewPrivileges` | None in v1 | Documented as a known gap; jails or Capsicum are a later decision |

### Host prerequisites (document in this WIP and later in setup docs)

Initial FreeBSD 15.1 amd64 package set from the `latest` repository (verify exact package names on the target host):

- `bash`, `git`, `go` (metaport at 1.26 in `latest`, which satisfies `go 1.26.6` in `go.mod`), `gmake`, `cmake`, `pkgconf`, `perl5`, `p5-Text-Template` if the OpenSSL Configure module check reports it missing, `python3`, `autoconf`, `automake`, `libtool`, `curl`, `ca_root_nss`, `jq`, `emscripten` (6.0.3; pulls in Node and `llvm-devel`), `npm`
- Bun is not a package: install the pinned `bun-v1.3.14` FreeBSD zip into the dev user's `~/.bun/bin` as described in "Toolchain Decisions". Do not install `bun-linux`.
- No `gcc`; the base `cc` (clang) is the C compiler. `unzip` and `fetch` come from base.
- On pkgbase installs, the base development packages that provide headers and static archives (`libc.a`, `libthr.a`) for the static server link
- Bun, Go, and npm available in the resolved dev user's PATH
- `pkg lock` on `emscripten` and Go after validation so routine upgrades cannot silently change the pinned versions
- Network access for FreeBSD packages, the Bun and SeaweedFS release downloads, Go toolchain/modules if needed, npm registry access for the vendored libopaque.js `npm install`, and repository/vendor operations

The exact `pkg install ...` line should be updated here once validated on a real host.

### Linux Issues Surfaced by This Review (fixed on Linux)

These pre-existing Linux behaviors were found while tracing the call graph and have since been fixed on Linux with developer approval. None of the fixes migrates or touches data, keys, secrets, or the database; existing deployments pick them up through the normal `*-update.sh` path. The FreeBSD work must preserve them.

- User-secret master memory protection. `crypto/user_secret_master.go` used to pass a 32-byte heap slice to `madvise(MADV_DONTDUMP)`, which Linux rejects with `EINVAL` because the address is not page-aligned, so the advice never applied. The key now lives in a dedicated anonymous page from `mmap` (`allocSecretPage` in `crypto/user_secret_master_linux.go`); `mlock` and `madvise` act on that page, and `crypto/user_secret_master_linux_test.go` checks alignment and the `madvise` result. Failures remain warnings rather than fatal so a host with a restrictive memory-lock limit still starts. The FreeBSD implementation adds its own `allocSecretPage`/`freeSecretPage`.
- rqlite and SeaweedFS no longer load `secrets.env`. `EnvironmentFile=` was removed from `systemd/rqlite.service` and `systemd/seaweedfs.service`. rqlited v10.0.0 reads no environment variables in server mode, and SeaweedFS 4.18 reads only `WEED_*` and a fixed set of cloud-credential names, none of which any Arkfile script writes into `secrets.env`. The update scripts reinstall the units and run `daemon-reload`; the change takes effect at each service's next restart. Separate service users for rqlite and SeaweedFS remain a later, signed-off change because they would require an ownership migration of existing data directories.
- `deploy.sh` copies only runtime artifacts (`bin`, `client`, `database`, `systemd`, `webroot`, `version.json`, `sbom.cdx.json`, `build-dependencies.json`) and removes `c-libs/` and `wasm/` from the install root. `vps-update.sh` and `local-update.sh` remove those two build-only directories as well, through `remove_stale_build_output_from_install_root` in `deploy-common.sh`, which deletes exactly those two names and refuses to act on `/` or on the build root.
- `/opt/arkfile/bin` is root-owned everywhere. `apply_arkfile_bin_ownership` in `deploy-common.sh` sets `root:0` on `bin/` after every recursive `chown -R arkfile:arkfile` in `dev-reset.sh`, `local-deploy.sh`, and `vps-first-deploy.sh`; `install_binaries_from_build` installs binaries as `root:0` on the update path; rollback restores root ownership; `02-setup-directories.sh` creates `bin/` as `root:0`; and `verify_ownership` skips `bin/` for the root-owned-file check while requiring everything under `bin/` to be root-owned. When adding the rc.d tree, any new directory that holds executables follows the same rule.

### Devuan/non-systemd Linux follow-on

Do not add Devuan to this WIP's success claims. Design the adapter so a later Linux service-manager backend can be added independently:

- Linux package/OS behavior remains separate from service-manager behavior.
- Future SysVinit support would install `/etc/init.d` scripts and use `update-rc.d`/`service`.
- OpenRC and runit remain distinct future adapters, not aliases for SysVinit.
- A Linux host without systemd fails clearly until its manager is implemented.

After Linux/systemd and FreeBSD/rc.d both pass their blocking gates, Devuan/SysVinit is a small follow-on plan rather than an expansion of this first implementation.

### Documentation updates (with the implementation)

- `AGENTS.md`: note Linux as primary deploy host; FreeBSD `dev-reset` experimental; root + `ARKFILE_DEV_USER` on FreeBSD; `fdre2e.sh` Linux-only; agents still must not invoke deploy scripts themselves. Update the Bun paragraph so FreeBSD installs the pinned upstream 1.3.14 FreeBSD binary (the 1.3.x-only and no-`bun upgrade` rules are unchanged), and update any emsdk 4.0.23 references when the Emscripten pin moves to 6.0.3.
- `docs/setup.md`: replace aspirational "BSD supported" with accurate Linux-primary / FreeBSD-experimental wording, FreeBSD package notes for this path, and the pinned Bun install procedure.
- When e2e is green, revise status in this file and soften "experimental" only to the extent proven (dev-reset + e2e-test, not prod-deploy).

### Follow-on considerations (out of scope here)

Production FreeBSD. Bun, Emscripten, npm, and the compilers are build-time tools; nothing on a running Arkfile host needs them. Today `prod-update.sh` builds on the production host itself, which puts that whole toolchain and package-registry access on the machine holding users' encrypted data. Because the shipped JavaScript is the trust anchor of the end-to-end encryption model, the stronger long-term design for both Linux and FreeBSD is a dedicated build host that produces the frontend bundle, WASM, and binaries once, records their hashes alongside the existing SBOM and SRI values, and lets production hosts verify and install those exact artifacts. That is a separate, signed-off change to the update model. The native upstream Bun binary means a FreeBSD production build, if ever needed, would not require the Linux compatibility layer.

Bun 1.3.x freeze. Bun 1.4.x is the Rust rewrite (the `bun-v1.4.0` tag has `Cargo.toml` and no `build.zig`); 1.4.2 (2026-09-05) is the latest stable release on 2026-10-08, with official Linux and native FreeBSD binaries and the same signed `SHASUMS256.txt`. `AGENTS.md` currently forbids 1.4. Staying on 1.3.14 indefinitely means a build tool that downloads registry packages and writes the security-critical bundle stops receiving fixes. Any move to 1.4.x is a project-wide decision, proven on Linux first (lockfile compatibility, bundler output under the SRI and e2e checks, `bun:test` behavior, `bun audit`, full e2e and Playwright), and then applied to FreeBSD with new pinned digests established by the procedure in "Toolchain Decisions".

## Non-goals during this initial project

- OpenBSD support
- FreeBSD aarch64
- FreeBSD releases below major version 15
- `local-deploy.sh` / `prod-deploy.sh` / `test-deploy.sh` / Caddy / deSEC on FreeBSD
- Playwright / `e2e-playwright.sh` / `fdre2e.sh` on FreeBSD
- Official FreeBSD ports/packages packaging
- Requiring or depending on the `sudo` package on FreeBSD
- Allowing shared libopaque, liboprf, libsodium, libfido2, libcbor, libcrypto, or zlib from FreeBSD ports in Arkfile binaries
- Rewriting scripts from bash to POSIX sh
- Duplicating the entire setup tree under a `freebsd/` directory
- Editing vendored upstream Makefiles to make them portable
- FreeBSD equivalents of the systemd sandbox directives (jails, Capsicum)
- Claiming Devuan, SysVinit, OpenRC, or runit support before a separate backend is implemented and tested
- Replacing simple bootstrap shell operations with repeatedly compiled Go utilities

## Implementation Order

1. Toolchain decisions are resolved (see "Toolchain Decisions").
2. Record a clean Linux amd64 baseline using the developer-run `dev-reset.sh` then `e2e-test.sh`.
3. Move the Linux Emscripten pin to 6.0.3 with `-sFAKE_DYLIBS=1` in `WASM_LIBOPAQUE_LDFLAGS`, and prove it on Linux with `dev-reset.sh`, `e2e-test.sh`, `e2e-playwright.sh`, and the WASM interop harness as a standalone change before any FreeBSD work depends on it. Add the Bun FreeBSD digests and the FreeBSD `print_bun_install_hint` branch to `build-config.sh` in the same or a following change.
4. Add `os-portable.sh`: host/service-manager detection, FreeBSD 15+/amd64 preflight, root/dev-user resolution, argument-safe privilege helpers, toolchain preflight, service API, portable tool helpers, and the GNU make shim; add the adapter test script.
5. Route all independent `sudo`/`SUDO_USER` logic in the dev-reset call graph through the shared helpers; convert invoked Bash shebangs to `/usr/bin/env bash`; move all checks ahead of the NUKE prompt.
6. Fix the known hard failures that are shared-script changes with no Linux behavior change: numeric root gid, `sed -i` and `stat -c` call sites, `pgrep`/`pkill` patterns, `ldd` parsing.
7. Add Go `ARKFILE_ENV_FILE` loading with the parsing parity test, FreeBSD user-secret-master protection (`mlock`, `MADV_NOCORE`, `procctl`, core limit) with tests, and the FreeBSD `agent status` process enumeration.
8. Add `rc.d/{arkfile,rqlite,seaweedfs}` and the newsyslog entry with systemd argument parity, `daemon(8)` supervision, chdir, file logging, loopback binds, and core suppression.
9. Stage both service-definition families in `build.sh` (with `BUILD_RCD` cleanup at every `BUILD_SYSTEMD` site); make `deploy.sh` the sole definition installer; wire service stop/start/enable/status/log operations through the adapter.
10. Add FreeBSD `pw` user/group creation and the privilege-helper changes across `01` through `04`.
11. Add platform-keyed SeaweedFS download + independently pinned FreeBSD SHA-256; remove component-owned service installation.
12. Refactor rqlite Go/git/dev-user handling and cached path; remove component-owned service installation.
13. Add the FreeBSD Bun digest preflight and dev-user `find_bun_binary` resolution, native FreeBSD Emscripten selection, the GNU make shim around the vendored WASM build, and the npm prerequisite.
14. Implement OS-specific server/CLI link flags, verification, and accurate build metadata without changing Linux fully static behavior.
15. Port `e2e-test.sh` host utilities and guidance, preserving test semantics.
16. Run shell syntax checks and the adapter test script, then developer-run Linux `dev-reset.sh` + `e2e-test.sh`; resolve every Linux regression before FreeBSD validation.
17. Validate on FreeBSD 15.1-RELEASE amd64: `go test ./...`, root reset with `ARKFILE_DEV_USER`, then non-root e2e.
18. Repeat the complete Linux reset + e2e gate after FreeBSD passes.
19. Documentation honesty pass (`AGENTS.md`, `docs/setup.md`, this file's Status); only then consider a separate Devuan/SysVinit follow-on.

## Exit Criteria

### Shared implementation

- [x] The three toolchain decisions are resolved and recorded in this file (2026-10-08)
- [ ] Linux builds with Emscripten 6.0.3 and passes `dev-reset.sh`, `e2e-test.sh`, `e2e-playwright.sh`, and the WASM interop harness before FreeBSD depends on it
- [ ] `build-config.sh` records `BUN_FREEBSD_X64_ZIP_SHA256` and `BUN_FREEBSD_X64_BIN_SHA256`, and the FreeBSD install hint prints the pinned procedure
- [ ] Host OS and service manager are detected independently; unsupported combinations fail before mutation
- [ ] All host, privilege, dev-user, and toolchain checks run before the NUKE confirmation on both platforms
- [ ] `os-portable.sh` centralizes root/dev-user/service/tool behavior with no remaining conflicting `$SUDO_USER` implementations in the call graph
- [ ] Shared scripts use a Bash path valid on Linux and FreeBSD without filesystem symlinks
- [ ] No shared script in the call graph names a `root` group
- [ ] Service definitions have one install owner (`deploy.sh`), both artifact families are staged deterministically, and every build-clean path removes both
- [ ] Arkfile loads an explicit env file internally without a root shell sourcing service-user-writable content, and the parsing parity test passes
- [ ] Shell syntax checks pass for every modified shell script
- [ ] The adapter test script verifies Linux/systemd and FreeBSD/rc.d command selection without mutating host services

### Blocking Linux regression gate

- [ ] Existing invocation remains `sudo bash scripts/dev-reset.sh`; Linux requires no new flags/environment
- [ ] `--force-rebuild-all`, `--force-rebuild-rqlite`, `--help`, and unknown-option behavior remain unchanged
- [ ] Existing systemd service names, paths, start order, status behavior, units, and log guidance remain unchanged
- [ ] Linux server remains fully static and current CLI linking policy is not weakened
- [ ] Developer-run Linux amd64 `dev-reset.sh` completes and leaves all three services healthy
- [ ] Linux `scripts/testing/e2e-test.sh` passes
- [ ] Linux `scripts/testing/e2e-playwright.sh` passes with the Emscripten 6.0.3 pin
- [ ] Go tests pass with the CGO environment documented in `AGENTS.md`
- [ ] The complete Linux reset + e2e gate is repeated after FreeBSD passes

### Blocking FreeBSD gate

- [ ] Preflight accepts FreeBSD 15.1-RELEASE amd64 and rejects FreeBSD <15 / non-amd64
- [ ] Root + `ARKFILE_DEV_USER` resolution works without the sudo package; all builds/git operations run as the dev user
- [ ] Preflight rejects a missing Bun, a non-1.3.x Bun, and a Bun binary whose SHA-256 does not match `BUN_FREEBSD_X64_BIN_SHA256`
- [ ] The pinned upstream Bun 1.3.14 FreeBSD binary runs `bun install --frozen-lockfile`, `bun audit`, `type-check`, `build:prod`, the TypeScript unit tests (`scripts/testing/test-typescript.sh`), and the WASM interop harness
- [ ] Emscripten 6.0.3 builds the OPAQUE WASM successfully, the interop harness passes, and a user registered through the Linux build logs in through the FreeBSD build and vice versa
- [ ] The FreeBSD server is fully static, and the CLI embeds vendored crypto/FIDO archives while dynamically linking only evidenced base-system runtime libraries
- [ ] FreeBSD user-secret-master uses native memory locking, no-core advice on a page-aligned buffer, `procctl` trace disable, and process core suppression
- [ ] `go test ./...` passes on the FreeBSD host
- [ ] rc.d scripts start, status, restart, and stop arkfile, rqlite, and seaweedfs reliably as `arkfile`
- [ ] rc.d services preserve loopback bindings, permissions, environment loading, working directories, pidfiles, per-service logs, and log rotation
- [ ] SeaweedFS FreeBSD amd64 asset downloads and verifies against an independently pinned SHA-256
- [ ] `build.sh --build-only` succeeds as the resolved dev user (Bun + WASM included)
- [ ] Root `dev-reset.sh` completes and leaves all three services healthy
- [ ] Non-root `scripts/testing/e2e-test.sh` passes against that instance, including the CLI agent tests
- [ ] `arkfile-client agent status` reports orphaned agent processes correctly on FreeBSD
- [ ] `AGENTS.md` and `docs/setup.md` describe Linux-primary / FreeBSD-experimental scope accurately

## Evidence to Record During Bring-Up

Record these in this document as they become known:

- Exact `pkg install` command validated on FreeBSD 15.1-RELEASE amd64 from the `latest` repository, and which packages were locked
- Bun: `sha256sum ~/.bun/bin/bun` output matching `BUN_FREEBSD_X64_BIN_SHA256`, `bun --version`, and the `gpg --verify SHASUMS256.txt.asc` result used to establish the pin; Emscripten, Node, npm, and `llvm-devel` versions used for the successful build
- Whether base install used distribution sets or pkgbase, and which base development packages were required
- Output format of FreeBSD `sha256sum` on a sample file, confirming it matches what the scripts parse
- Pinned SHA-256 for SeaweedFS `freebsd_amd64.tar.gz` and the trusted acquisition procedure used to establish it
- `file` and `ldd` output for Arkfile server, client, and admin binaries, identifying every accepted FreeBSD base dependency; `file` and `ldd` output for `rqlited` and `weed`
- rc.d/sysrc definitions, `daemon(8)` arguments, pidfile locations, log locations and modes, newsyslog entry, and restart behavior
- `procstat -l` core limit and `procctl` trace status for the running arkfile process
- The dev user's login class `memorylocked` limit and whether the CLI agent `mlock` calls succeed
- Linux before/after reset + e2e results
- FreeBSD `go test`, reset, and e2e results

Any new dynamic ports dependency, shared crypto dependency, weakening of Linux static verification, a non-static FreeBSD server, divergent Emscripten versions between Linux and FreeBSD, a Bun binary other than the pinned upstream release, use of `lang/bun-linux` or the Linux compatibility layer, root build fallback, root sourcing of `secrets.env`, or Linux dev-reset behavior change is a new locked decision requiring developer sign-off. It must not be treated as an implementation detail.
