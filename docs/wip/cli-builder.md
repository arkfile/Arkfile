# arkfile-client Cross-Platform Build Tooling

## Reasoning

`arkfile-client` is the portable, privacy-preserving way for owners and operators to encrypt, upload, download, decrypt, share, and manage vault data outside the browser. It uses the same OPAQUE and Argon2id/file-crypto model as the TypeScript frontend, and it must keep streaming behavior suitable for large files on constrained devices. Today the canonical build path is tied to the Linux server deploy scripts (`build.sh` via `dev-reset.sh` / `local-deploy.sh` / production update paths). That is correct for developing the full stack on a Linux host, but it is the wrong shape for distributing a standalone CLI to users on many operating systems. This WIP covers build and packaging tooling so a developer or packager can produce a trustworthy `arkfile-client` on each supported target without inventing a second encryption path or a second upload/download path.

This work is intentionally separate from `docs/wip/freebsd-dev.md`. FreeBSD server `dev-reset` proves Arkfile as a host (services, SeaweedFS, rqlite, e2e). FreeBSD appears here only as a later client build-host target (Group B). Completing one does not require completing the other. Shared CGO, vendored C library, and link-verification helpers in `scripts/setup/build-config.sh` and related build scripts must stay common so policy does not drift.

## Status

Locked decisions below define the Group A implementation target. No dedicated standalone client-builder entrypoint exists yet beyond the full-stack `build.sh` path. Code changes have not started; this document is the source of truth for the first implementation pass.

Product priority for this WIP: ship `arkfile-client` build infra for all Group A operating systems first. FreeBSD server work (`freebsd-dev.md`) and Group B+ client targets wait until Group A is green.

## Overview

`arkfile-client` requires CGO. It links the vendored OPAQUE stack (libopaque, liboprf, libsodium) and, for hardware security keys, the vendored FIDO stack (libfido2, libcbor, OpenSSL libcrypto, zlib), with a small set of OS-provided runtime libraries such as `libudev` on Linux. That means a pure-Go binary built with `CGO_ENABLED=0` is not an acceptable product path. Cross-compilation of CGO targets is a poor first design for this project: each OS needs its own toolchain, headers, and link policy. Prefer native builds on each target, with one shared recipe driven by existing platform detection rather than a forest of one-off scripts.

There must remain only one way for the Go CLI to encrypt/upload and download/decrypt. Build tooling may vary by host; crypto and command behavior must not. Packaging must not pull host shared libsodium or other ports/system crypto into the CLI when vendored archives are intended. Documentation must stay honest about which platforms are proven versus experimental.

## Locked Decisions (Group A)

| Decision | Choice |
|---|---|
| Priority | `arkfile-client` build infra for all Group A OSes in one implementation pass |
| Entrypoint | `scripts/setup/build-client.sh` |
| Scope of binary | `arkfile-client` only; `arkfile-admin` stays server-deploy / `build.sh` only |
| Build workspace | `/tmp/arkfile-client-build` as the sole `BUILD_ROOT` for this recipe (not `/var/tmp/arkfile-build`) |
| Install path | `/opt/arkfile-cli/arkfile-client` via sudo (must not overwrite `/opt/arkfile/bin/arkfile-client`) |
| Containers | None for Group A; native hosts only; no podman/docker builders |
| Architectures | amd64 only for Group A |
| Devuan reference | Devuan 6 Excalibur (latest stable); document `libudev` vs `eudev` package names |
| Version embedding | Shared `cli_go_ldflags` injects release version and short git commit; carries forward to later OS groups |
| Version UX | `arkfile-client -V` (and existing version paths) print version and short commit, e.g. `arkfile-client vX.Y.Z (commit abcdef1)` |
| e2e override | `e2e-test.sh --client-path /path/to/binary`; default remains `/opt/arkfile/bin/arkfile-client` |
| e2e path rules | `--client-path` must be absolute and executable; reject paths under `/tmp`; admin always `/opt/arkfile/bin/arkfile-admin` |
| Opaque / libsodium in-tree `.a` | Acceptable for Group A (current build scripts write into `vendor_c`); FIDO and final binary use the client build root |
| Isolation from `dev-reset` | `dev-reset` must not wipe `/tmp/arkfile-client-build` or `/opt/arkfile-cli`; standalone install must survive a reset |

## Relationship to Other Work

Server deploy scripts remain the source of truth for building CLIs as part of a full Arkfile instance on Linux (`/var/tmp/arkfile-build` and `/opt/arkfile`). This WIP adds a client-focused path that builds and installs `arkfile-client` without requiring SeaweedFS, rqlite, systemd, or a destructive reset. Shared pieces that both server and client builds need -- platform detection, vendored C builds, CLI CGO flags, link verification, and version ldflags -- are improved once in `build-config.sh` / `build-libopaque.sh` / `build-libfido2.sh` and reused. Do not fork a second copy of those rules under a separate `cli-builder` C-pipeline tree.

## Platform Groups and Priority

### Group A -- First implementation pass (locked)

Native builds on glibc Linux amd64, with family-specific dependency notes but one build recipe:

- Debian-family: Debian, Ubuntu, Devuan 6 Excalibur
- RHEL-family: RHEL, Alma, Rocky, Fedora
- SUSE-family: openSUSE, SLES

This group reuses the link model already documented for Linux CLIs (vendored C archives linked statically; OS libraries such as libudev and libc linked dynamically). Success means documented dependency lists per family (apt / dnf / zypper), `detect_package_os_family` awareness including SUSE, a single client entrypoint that builds under `/tmp/arkfile-client-build` and installs to `/opt/arkfile-cli/arkfile-client`, verified linking, and functional proof via `e2e-test.sh` against both the deploy client and the standalone install (see Proof Loop).

Devuan belongs here rather than Group B because client builds care about glibc, apt, and CGO/FIDO headers, not about whether the machine runs systemd. The same Debian-family recipe applies, with an explicit note that udev development and runtime packages may be `libudev` or `eudev` depending on the Devuan release. A green Devuan client build does not mean Arkfile server deploy on Devuan is supported. Non-systemd service management for hosting Arkfile remains out of scope here and is covered separately in `freebsd-dev.md`.

### Group B -- Later (not in this pass)

Alpine amd64 (musl), FreeBSD 15+ amd64 as a client build host only, macOS (Apple Silicon first). No containers in Group A; Alpine container helpers such as `alpine-build-test.sh` stay out of scope until Group B. FreeBSD client link policy must stay consistent with `freebsd-dev.md`: vendored crypto and FIDO archives static; only evidenced base-system libraries may be dynamic.

### Group C -- Later

OpenBSD amd64 (best-effort). Linux aarch64 for already-supported recipes as a second architecture, not a new OS family.

### Group D -- Later

Windows amd64. Separate toolchain and packaging; must not gate Groups A through C.

## Tooling Shape (locked for Group A)

```text
scripts/setup/
  build-client.sh          # client-only entrypoint (Group A)
  build-config.sh          # shared: families, CGO flags, link verify, version ldflags
  build-libopaque.sh       # reused (in-tree vendor_c .a acceptable for Group A)
  build-libfido2.sh        # reused (BUILD_ROOT-relative FIDO prefix)
  build.sh                 # full stack; still builds client+admin for /opt/arkfile

scripts/testing/
  e2e-test.sh              # default deploy client; --client-path for standalone

config/version.go          # Version + GitCommit vars injected via shared ldflags
cmd/arkfile-client/        # -V prints version + short commit

/tmp/arkfile-client-build/           # build-client BUILD_ROOT only (ephemeral)
/opt/arkfile-cli/arkfile-client      # installed standalone (survives dev-reset)
/opt/arkfile/bin/arkfile-client      # deploy client (default e2e)
/opt/arkfile/bin/arkfile-admin       # e2e admin always
```

`build-client.sh` must:

1. Set `ARKFILE_BUILD_DIR=/tmp/arkfile-client-build` (or equivalent) before sourcing `build-config.sh`, so it never uses `/var/tmp/arkfile-build`.
2. Build only the vendored C libraries needed for the CLI, then build `arkfile-client` with existing CLI FIDO CGO flags.
3. Run link verification (`verify_cli_binary_linking` / `file` + `ldd`).
4. Install with sudo to `/opt/arkfile-cli/arkfile-client` (create directory, install binary, sane permissions).
5. Not call `dev-reset.sh`, not rebuild TypeScript or server WASM, and not build `arkfile-admin`.

Family-specific dependency lists live as docs/hints (and package-family detection improvements in `build-config.sh`). Duplicating the entire C build pipeline per distro is not allowed.

## Version Embedding (locked)

Change `config.Version` from a const to a var and add `config.GitCommit`. Inject both from shared `cli_go_ldflags` in `build-config.sh` using `git describe` (or the existing release version) and `git rev-parse --short HEAD`, with safe fallbacks when git metadata is unavailable. Both `build.sh` and `build-client.sh` must use that helper so deploy and standalone clients report the same scheme. Later OS groups reuse the same mechanism; do not invent a client-only version path.

`arkfile-client -V`, `--version`, and the `version` command print both the version number and the short commit.

## e2e Parity Proof (locked)

`e2e-test.sh` keeps the default client at `/opt/arkfile/bin/arkfile-client`. An optional flag selects the standalone install:

```text
bash scripts/testing/e2e-test.sh
bash scripts/testing/e2e-test.sh --client-path /opt/arkfile-cli/arkfile-client
```

`--client-path` must be an absolute path to an executable file. Paths under `/tmp` are rejected so tests never run against a world-writable sticky directory. `arkfile-admin` always remains `/opt/arkfile/bin/arkfile-admin`.

### Proof loop (Debian first, then other Group A hosts)

1. `sudo bash scripts/dev-reset.sh`
2. `bash scripts/testing/e2e-test.sh` (deploy client baseline)
3. `sudo bash scripts/setup/build-client.sh` (build workspace + install to `/opt/arkfile-cli`)
4. `bash scripts/testing/e2e-test.sh --client-path /opt/arkfile-cli/arkfile-client`
5. `/opt/arkfile-cli/arkfile-client -V` shows version and short commit
6. After another `dev-reset`, confirm `/opt/arkfile-cli/arkfile-client` still exists and e2e with `--client-path` still works

Identical pass/fail between steps 2 and 4 is the bar that the standalone recipe did not invent a second client.

## Link and Crypto Policy

Keep the threat model and crypto paths unchanged: OPAQUE via libopaque CGO, Argon2id and file encryption on the client, hardware keys via vendored libfido2 where supported. Do not introduce a `CGO_ENABLED=0` almost-client for release. Do not accept host shared libsodium (or other host crypto) when vendored archives are the project standard. Group A keeps the current documented Linux CLI link model. Later groups each get an explicit allowed dynamic library set from real `ldd` / `otool` evidence. Any new dynamic dependency is a deliberate decision, not an accident of pkg-config.

## Documentation and Honesty

Until Group A is green, docs should say Linux full-stack build via `dev-reset` / `build.sh` is the primary proven path, and standalone multi-OS client builds are in progress. When Group A lands, document exact packages per family, one build command (`sudo bash scripts/setup/build-client.sh`), build workspace, install path, and runtime library needs (`libudev` / `eudev`). Do not list Alpine, macOS, FreeBSD client, OpenBSD, or Windows as supported while they remain later groups. Do not imply that a green Devuan client build means Arkfile server deploy on Devuan is supported. User-facing FAQ material stays in Q&A prose if any client distribution questions are added later; packager and developer detail stays in setup docs or this WIP.

## Non-Goals

This WIP does not replace `dev-reset.sh` or production deploy scripts. It does not deliver FreeBSD or OpenBSD server hosting. It does not add a second CLI encrypt/upload or download/decrypt implementation. It does not require Playwright, browser WASM, Bun, or Emscripten for client builds. It does not build `arkfile-admin` via the client recipe. It does not use containers for Group A. It does not make Windows, OpenBSD, Alpine, macOS, or FreeBSD client a blocker for the Group A pass. It does not prioritize exotic cross-compilation from a single builder host over native recipes that work. It does not teach `dev-reset` to clean `/tmp/arkfile-client-build` or `/opt/arkfile-cli`.

## Sequencing Relative to FreeBSD Server Work

Product priority is distributing / building `arkfile-client` for users: complete Group A before investing in the full FreeBSD server reset. Keep this document’s FreeBSD cell as client build host only (Group B). Shared CGO/link/version helpers stay common. Do not run a full FreeBSD server port and a full multi-OS client matrix as one interleaved stream against the same build scripts.

## First Useful Release Cut (revised)

Group A only: all listed glibc Linux amd64 families, one entrypoint, documented deps, verified linking, install under `/opt/arkfile-cli`, version+commit via `-V`, and e2e parity with `--client-path`. Alpine, macOS, FreeBSD client, OpenBSD, and Windows remain later groups with honest status labels.

## Open Decisions (later groups / packaging polish)

How much of `alpine-build-test.sh` is absorbed versus kept as an optional regression helper in Group B. Whether Linux family builders may use podman images after Group A, and under what consent rules. Precise FreeBSD and macOS allowed dynamic library lists from measured link output. Windows packaging format and the minimum MFA feature set for a first Windows binary. Whether checksums are published beside installed or distributed binaries. Whether opaque/libsodium builds should later move fully out-of-tree under the client build root (strict isolation beyond the Group A seam).
