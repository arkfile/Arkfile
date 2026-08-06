# arkfile-client Cross-Platform Build Tooling

## Reasoning

`arkfile-client` is the portable, privacy-preserving way for owners and operators to encrypt, upload, download, decrypt, share, and manage vault data outside the browser. It uses the same OPAQUE and Argon2id/file-crypto model as the TypeScript frontend, and it must keep streaming behavior suitable for large files on constrained devices. Today the canonical build path is tied to the Linux server deploy scripts (`build.sh` via `dev-reset.sh` / `local-deploy.sh` / production update paths). That is correct for developing the full stack on a Linux host, but it is the wrong shape for distributing a standalone CLI to users on many operating systems. This WIP covers build and packaging tooling so a developer or packager can produce a trustworthy `arkfile-client` on each supported target without inventing a second encryption path or a second upload/download path.

This work is intentionally separate from `docs/wip/freebsd-dev.md`. FreeBSD server `dev-reset` proves Arkfile as a host (services, SeaweedFS, rqlite, e2e). FreeBSD appears here only as a client build-host target. Completing one does not require completing the other, though they should share CGO, vendored C library, and link-verification helpers in `scripts/setup/build-config.sh` and related build scripts so policy does not drift.

## Status

High-level outline. Platform groupings and sequencing below are the working plan; detailed package lists, artifact layouts, and release automation remain to be locked during implementation. No dedicated standalone client-builder entrypoint exists yet beyond the full-stack `build.sh` path and the Alpine-oriented `scripts/testing/alpine-build-test.sh` helper.

## Overview

`arkfile-client` requires CGO. It links the vendored OPAQUE stack (libopaque, liboprf, libsodium) and, for hardware security keys, the vendored FIDO stack (libfido2, libcbor, OpenSSL libcrypto, zlib), with a small set of OS-provided runtime libraries such as `libudev` on Linux. That means “download a pure-Go binary built with `CGO_ENABLED=0`” is not an acceptable product path. Cross-compilation of CGO targets is possible in theory but is a poor first design for this project: each OS needs its own toolchain, headers, and link policy. Prefer native builds on each target (or a same-OS builder VM/container with developer consent for podman only), with one shared recipe driven by existing platform detection rather than a forest of one-off scripts.

There must remain only one way for the Go CLI to encrypt/upload and download/decrypt. Build tooling may vary by host; crypto and command behavior must not. Packaging must not pull host shared libsodium or other ports/system crypto into the CLI when vendored archives are intended. Documentation must stay honest about which platforms are proven versus experimental.

## Relationship to Other Work

Server deploy scripts remain the source of truth for building CLIs as part of a full Arkfile instance on Linux. This WIP adds a client-focused path that builds `arkfile-client` (and, where useful, `arkfile-admin` if the same flags apply) without requiring SeaweedFS, rqlite, systemd, or a destructive reset. Shared pieces that both server and client builds need -- platform detection, vendored C builds, CLI CGO flags, and link verification -- should be improved once in `build-config.sh` / `build-libopaque.sh` / `build-libfido2.sh` and reused. Do not fork a second copy of those rules under a `cli-builder` tree.

## Platform Groups and Priority

### Group A -- Prove the matrix (first)

Native builds on glibc Linux amd64, with family-specific dependency notes but one build recipe: Debian, Ubuntu, and Devuan`*`; RHEL, Alma, Rocky, and Fedora; openSUSE and SLES. This group reuses the link model already documented for Linux CLIs (vendored C archives linked statically; OS libraries such as libudev and libc linked dynamically). Success means a documented dependency list per family, a single client-oriented build entrypoint that produces a verified binary, and a short post-build functional check against a known Arkfile instance (login plus a small encrypt/upload and download/decrypt round trip, without inventing a second client code path) and/or the offline decryption of a known, pre-constructed, encrypted .arkbackup file.

`*` - Devuan belongs here rather than Group B because client builds care about glibc, apt, and CGO/FIDO headers, not about whether the machine runs systemd. The same Debian-family recipe should apply, with an explicit note that udev development and runtime packages may be `libudev` or `eudev` depending on the Devuan release. Non-systemd service management for hosting Arkfile remains out of scope for this WIP and is covered separately in `freebsd-dev.md` as a possible later Linux adapter.

### Group B -- Same Unix story, different libc or packaging (second)

Alpine amd64 (musl), where `alpine-build-test.sh` and Alpine hints in `build-config.sh` already exist and should be folded into or aligned with the new tooling rather than left as a parallel experiment. FreeBSD 15+ amd64 as a client build host only (not server `dev-reset`). macOS with Apple Silicon first and Intel second if still needed. These targets share Unix assumptions and USB HID for FIDO, but they force real differences in libc, package managers, and dynamic library sets. FreeBSD client link policy should stay consistent with the locked CLI direction in `freebsd-dev.md`: vendored crypto and FIDO archives static; only evidenced base-system libraries may be dynamic; reject unexpected ports crypto.

### Group C -- Harder Unix / lower immediate demand (third)

OpenBSD amd64 as best-effort until Groups A and B are green. Linux aarch64 for the Group A/B operating systems that matter most (for example Debian/Ubuntu/Devuan arm64 and Alpine arm64), treated as a second architecture of an already-supported recipe rather than a new OS family.

### Group D -- Different product surface (last)

Windows amd64. This is a separate toolchain, packaging, path, and likely FIDO/HID story. It must not gate Groups A through C. An acceptable early Windows bar may be core crypto and TOTP with hardware-key support following later, if that is the only way to ship a correct partial client without pretending full parity exists.

## Suggested Shape of the Tooling

Prefer a thin client-focused entrypoint (for example under `scripts/setup/` or `scripts/client/`) that sources `build-config.sh`, builds only the vendored C libraries needed for the CLI, builds `arkfile-client` with the existing CLI FIDO CGO flags, runs link verification, and writes artifacts to a clear output directory. It must not call `dev-reset.sh`, must not require root by default, and must not rebuild TypeScript or server WASM. Family-specific dependency documents or small helper snippets are fine; duplicating the entire C build pipeline per distro is not.

Native build first; optional later use of podman for Linux family builders only with express developer consent per AGENTS.md, and never docker. Do not treat a FreeBSD OCI image on a Linux host as a FreeBSD build. Validation of FreeBSD and macOS clients means real FreeBSD and macOS hosts or VMs.

Post-build verification should include `file` / `ldd` (or platform equivalent) against the allowed dependency policy, plus a minimal functional check using the built binary against a running Arkfile instance when one is available. Full `e2e-test.sh` remains the server-stack proof and is not the default bar for every client OS cell.

## Link and Crypto Policy (outline)

Keep the threat model and crypto paths unchanged: OPAQUE via libopaque CGO, Argon2id and file encryption on the client, hardware keys via vendored libfido2 where supported. Do not introduce a `CGO_ENABLED=0` “almost client” for release. Do not accept host shared libsodium (or other host crypto) when vendored archives are the project standard. Linux Group A keeps the current documented CLI link model. Alpine, FreeBSD, OpenBSD, and macOS each get an explicit allowed dynamic library set recorded from real `ldd` / `otool` evidence. Any new dynamic dependency is a deliberate decision, not an accident of pkg-config.

## Documentation and Honesty

Until a group is green, docs should say Linux full-stack build via `dev-reset` / `build.sh` is the primary proven path, and standalone multi-OS client builds are experimental or in progress per group. When a group lands, document exact packages, one build command, artifact location, and runtime library needs (for example `libudev` or `eudev` on Debian-family and Devuan hosts). Do not list OpenBSD or Windows as supported while they remain Group C/D. Do not imply that a green Devuan client build means Arkfile server deploy on Devuan is supported. User-facing FAQ material stays in Q&A prose if any client distribution questions are added later; packager and developer detail stays in setup or this WIP.

## Non-Goals

This WIP does not replace `dev-reset.sh` or production deploy scripts. It does not deliver FreeBSD or OpenBSD server hosting. It does not add a second CLI encrypt/upload or download/decrypt implementation. It does not require Playwright, browser WASM, Bun, or Emscripten for client builds. It does not make Windows or OpenBSD a blocker for the first useful release of the tooling. It does not prioritize exotic cross-compilation from a single builder host over native recipes that work.

## Sequencing Relative to FreeBSD Server Work

If the product priority is distributing `arkfile-client` to users, advance this WIP through Group A and then Group B (Alpine, FreeBSD client, macOS) before investing in the full FreeBSD server reset. If the product priority is Arkfile as a FreeBSD vault host, follow `freebsd-dev.md` first and keep this document’s FreeBSD cell as “client build host only.” In either case, do the small shared CGO/link cleanup once so both projects consume the same helpers. Do not run a full FreeBSD server port and a full multi-OS client matrix as one interleaved stream against the same build scripts.

## First Useful Release Cut

A practical first ship of the tooling is Group A (including at least one Devuan amd64 validation host alongside Debian/Ubuntu) plus Alpine plus macOS arm64: documented deps, one client build entrypoint, verified linking, and a short functional check. Add FreeBSD client next. Leave OpenBSD and Windows for later groups with honest status labels.

## Open Decisions for Later Locking

Exact script path and name for the client-only entrypoint. Whether `arkfile-admin` is built by the same recipe or stays server-deploy-only. Artifact naming, version embedding, and whether checksums are published beside binaries. How much of `alpine-build-test.sh` is absorbed versus kept as a regression helper. Whether Linux family builders may use podman images, and under what consent rules. Which Devuan release and udev package set (`libudev` vs `eudev`) is the reference for Debian-family docs. Windows packaging format and the minimum MFA feature set for a first Windows binary. Precise FreeBSD and macOS allowed dynamic library lists from measured link output.
