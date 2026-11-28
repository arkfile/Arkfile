# Kotlin and Compose Multiplatform App

## Overview

Arkfile will grow a third client, written in Kotlin with Compose Multiplatform, for Android, Linux, Windows, and Mac, in that order. It is a native application. It does not embed a browser, a system WebView, Chrome, Chrome Custom Tabs, or Firefox. The same Kotlin sources draw the interface and implement the vault protocol on every platform. Android is a sideloaded APK distributed without the Google Play Store. The desktops are JVM applications packaged after Android reaches full parity.

The app is a peer of the TypeScript web frontend and of `arkfile-client`, not a replacement for either. It implements the same OPAQUE authentication, the same Argon2id key derivation, the same version-2 owner FEK envelopes, the same AAD-bound AES-256-GCM metadata and chunk encryption, the same share envelopes, and the same `.arkbackup` v2 bundle format. Files, shares, and backups written by this app must open cleanly in `arkfile-client` and in the web frontend, and the reverse must hold as well.

Nothing in this document is implemented yet. `arkfile-client` remains the proven command-line client, including hardware security keys and the Linux account-key agent. The website remains the browser client.

## Prerequisites (Existing Bugs, Security Gaps, and Repo Isolation)

Resolve the following items in the existing repository BEFORE starting Kotlin/Compose app implementation. They fix real latent bugs in the current Go/C OPAQUE layer, unblock RFC 9106 native Argon2id, and keep the new Gradle tree isolated from server and CLI builds.

1. **[OK] Fix the 32-byte vs 64-byte `export_key` heap buffer overflow in `auth/opaque_client.go` (and scrub C-heap secret buffers).** Fixed in `auth/constants.go`, `auth/opaque_client.go`, and `auth/opaque_multi_step.go`: `ClientFinalizeRegistration` and `ClientRecoverCredentials` now allocate `OPAQUE_EXPORT_KEY_LEN` (64 bytes, `crypto_hash_sha512_BYTES`) instead of 32 bytes; `zeroCBytes` now uses compiler-barriered `sodium_memzero`; all secret C-heap copies (`cPassword`, `cUsrCtx`, `cSec`, `cServerPrivateKey`, `cUserRecord`, `cAuthUServer`, `cAuthUClient`) are scrubbed before `C.free`; error paths zero partial secret buffers; and unit tests in `auth/opaque_test.go` verify full 64-byte round-trip equality and repeated wrong-password safety. (Still validate via `dev-reset.sh` + `e2e-test.sh` before deploying.)
2. **[OK] Add explicit `sodium_init()` initialization to the native C wrapper.** Added `wrap_sodium_init()` in `auth/opaque_wrapper.h` / `auth/opaque_wrapper.c`, invoked once from `auth` package `init()` in `auth/opaque_multi_step.go` (failing closed via panic if `< 0`), and verified by `TestSodiumInitializedAtPackageInit`. The upcoming Kotlin JNI library (`arkfile_jni.c`) must likewise invoke `sodium_init()` in `JNI_OnLoad` plus an idempotent guard.
3. **Vendor and pin `phc-winner-argon2` under `vendor_c/`.** Libsodium's public `crypto_pwhash_argon2id` API cannot be used for Arkfile key derivation because it hardcodes a 16-byte salt (`crypto_pwhash_argon2id_SALTBYTES = 16U`) and `parallelism = 1`, whereas Arkfile uses 32-byte salts everywhere and requires full RFC 9106 `(t, m_kib, p, salt, saltlen, outlen)` support. Vendor the official C reference implementation (`phc-winner-argon2`, CC0 / Apache-2.0) under `vendor_c/` at a pinned commit recorded in `scripts/setup/build-config.sh` and fetched by `scripts/setup/ensure-vendor-c.sh`.
4. **Isolate the in-repo Gradle workspace from existing server, CLI, and SBOM workflows.** Place the Kotlin project under `clients/kotlin/` (distinct from `client/static/`, which is the web frontend). Update `scripts/setup/build.sh` so the `syft dir:.` SBOM scan excludes `./clients/kotlin/**` (preventing Gradle caches and Android/Kotlin build artifacts from polluting the server SBOM). Update `.gitignore` to ignore `clients/kotlin/**/.gradle/`, `clients/kotlin/**/build/`, `clients/kotlin/local.properties`, generated `jniLibs/`, and all signing artifacts (`*.apk`, `*.jks`, `*.keystore`, `*.p12`). Confirm `scripts/dev-reset.sh` and `scripts/setup/build-client.sh` never delete `/tmp/arkfile-kotlin-build`.

## Goal

Ship one native application that looks like a sibling of the website on Android, Linux, Windows, and Mac (in that priority order) and reaches **full feature parity with `arkfile-client` and the web frontend** without weakening Arkfile's end-to-end privacy model.

Android comes first as a self-signed sideloaded APK (no Google Play Store). Linux comes second (X11/XLibre, no Wayland), proven on the developer's Linux host before Windows or Mac work begins. Windows comes third. Mac comes fourth. A later platform does not block an earlier one, and iOS is out of scope.

Although the target is full parity (including creating and opening custom-password files with hints, owner tags, batch transfers, `.arkbackup` export/offline decrypt/manifest, Verify File, full MFA management and recovery, OPAQUE re-registration, contact info, billing/PAYG/Bitcart/OOB/subscriptions, and optional Dual Unlock Shortcut), implementation proceeds in ordered, independently verified milestones so groundwork and core vault operations are proven end-to-end before layering on the remaining parity features.

## Locked Decisions

| Decision | Choice |
|---|---|
| Repository layout | Everything in this repo under `clients/kotlin/` |
| Target platforms & order | Android first, then Linux, then Windows, then Mac (no iOS) |
| Feature scope | Full feature parity with `arkfile-client` and the web frontend (including creating new custom-password files), delivered in ordered milestones |
| Android distribution | Self-signed sideloaded APK only; no Play Store, no Play Services, no Firebase, no analytics or crash reporters |
| Android application ID & label | `net.arkfile.app` (`net.arkfile.app.debug` for debug builds); launcher label `Arkfile` |
| Android SDK & ABI | `minSdk = 28` (Android 9), `targetSdk = 35`; `arm64-v8a` only for release APKs (optional `x86_64` in debug builds only if local emulator testing is used) |
| Development tooling | Cursor/VSCodium + CLI (`sdkmanager`, `./gradlew`, `adb`) without Android Studio; IntelliJ IDEA strictly optional |
| Native C crypto stack | Vendored `libsodium` + `liboprf` + `libopaque` + `phc-winner-argon2` compiled out-of-tree under `/tmp/arkfile-kotlin-build` into one self-contained `libarkfile_native` shared library per target |
| HTTP auth mode | `Authorization: Bearer` + JSON refresh/logout bodies only; HTTP cookie storage strictly disabled (no CSRF cookie interaction) |
| MFA support | TOTP enrollment/login, backup-code Path A/B recovery, and MFA management; hardware security keys remain on `arkfile-client` |
| Account Key default lifecycle | In-memory only; lock on background by default, after frontend-comparable idle timeout (15-min default inactivity, 1-4h configurable TTL), on explicit lock, on logout, and on session end |
| Optional Dual Unlock Shortcut | Opt-in Long PIN + Android Keystore two-layer wrap bounded strictly to the active server session (max 24h absolute / 6h idle) |
| Sideload APK updates | Opt-out (default on, clearly toggleable) zero-telemetry in-app check against an Ed25519-signed manifest (`release.json`) published by the Arkfile Open Source Project, with APK SHA-256 verification before install |
| Linux desktop target | X11 / XLibre only (no Wayland); `.deb` / `.rpm` / AppImage via `jpackage` |
| Desktop signing (first release) | Unsigned sideload builds with published SHA-256 checksums and detached Ed25519 signatures (plus required ad-hoc `codesign -` on macOS Apple Silicon so binaries launch); paid Windows Authenticode / Apple Developer ID notarization deferred |

## Background

The web frontend and `arkfile-client` already agree under unit tests, conformance fixtures (`crypto/testdata/argon2-conformance-vectors.json` and `crypto/testdata/crypto-conformance-v2.json`), end-to-end runs (`scripts/testing/e2e-test.sh`), and Playwright tests (`scripts/testing/e2e-playwright.sh`). A third client written in Kotlin starts with two proven reference implementations and golden fixtures, making interoperability verification straightforward rather than speculative.

Other architectures were considered and set aside. A Trusted Web Activity or Android System WebView depends on Chromium. An embedded GeckoView engine is still a bundled browser. Go UI toolkits (Fyne, Gio) can reuse Go crypto directly, but recreating and maintaining a consistent custom design system across Android and three desktops is less flexible than Compose. Flutter can paint one themed UI across all four platforms, but safely streaming 6 GB files through Android's Storage Access Framework (`content://` URIs) still requires writing a Kotlin plugin underneath Dart. TypeScript desktop/mobile wrappers (Tauri, Electron) embed webviews, which this project rules out, and React Native neither runs the existing browser TypeScript/WASM stack nor provides a strong Linux desktop target.

Compose Multiplatform is native to Android (giving direct Kotlin access to SAF, Foreground Services, and Android Keystore) while sharing both UI and vault protocol code with Linux, Windows, and Mac. Desktop builds run on a bundled JVM packaged with `jpackage`, which brings a larger download and slower cold start than `arkfile-client`. That tradeoff is accepted; real transfer performance is dominated by network I/O, disk I/O, and Argon2id, not Compose rendering.

## Native Crypto and JNI Layer

### Single Self-Contained Native Library (`libarkfile_native`)

Compile all required C cryptography into **one self-contained shared library** per target (`libarkfile_native.so` on Android and Linux, `arkfile_native.dll` on Windows, `libarkfile_native.dylib` on macOS) with `-fvisibility=hidden` so only the JNI entry points are exported. Statically linking `libsodium.a`, the needed `liboprf` / `libopaque` objects, and `phc-winner-argon2` into one shared library avoids Android/Windows multi-library `dlopen` ordering issues and guarantees desktop builds never accidentally link a host system `libsodium`.

### Argon2id (Why `crypto_pwhash_argon2id` Must Not Be Used)

Do NOT call libsodium's public `crypto_pwhash_argon2id` function. In `vendor_c/jedisct1/libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c` (lines 167-171), it hardcodes `saltlen = 16` (`crypto_pwhash_argon2id_SALTBYTES`) and `parallelism = 1`. Every Arkfile key derivation uses a **32-byte salt** (`deriveContextSalt` SHA-256 output for owner Account/Custom keys, 32-byte random salts for share envelopes, and the 32-byte salt in `crypto/testdata/argon2-conformance-vectors.json`), and share envelopes/future configs must honor RFC 9106 `parallelism`. Do not reach into libsodium's private internal `argon2.h` header either, as it is not part of libsodium's public API.

Instead, compile the vendored `phc-winner-argon2` C sources into `libarkfile_native` and expose one JNI entry point `argon2idHashRaw(password: ByteArray, salt: ByteArray, tCost: Int, mCostKiB: Int, parallelism: Int, outLen: Int): ByteArray` that validates bounds, executes `argon2id_hash_raw`, zeroes temporary C buffers with `sodium_memzero`, and throws on non-zero return codes. Platform AES-256-GCM (`javax.crypto.Cipher` with `AES/GCM/NoPadding`) uses hardware AES acceleration on both Android and desktop JVMs and can stay on the platform provider.

### OPAQUE JNI Surface and Buffer Contract

OPAQUE stays on the vendored `libopaque` + `liboprf` + `libsodium` C stack; do not write a pure-Kotlin OPAQUE implementation. The JNI wrapper (`clients/kotlin/native/arkfile_jni.c`) calls `libopaque` directly (not `auth/opaque_wrapper.c`, which rejects `NULL` export keys and logs to `stderr`) and exposes four client operations matching `auth/opaque_client.go`:

- `opaqueCreateRegistrationRequest(password)` -> `(usrCtx, M)` where `M` is `OPAQUE_REGISTER_REQUEST_LEN` (32 bytes) and `usrCtx` is `OPAQUE_REGISTER_USER_SEC_LEN + pwdLen` (`34 + pwdLen` bytes).
- `opaqueFinalizeRegistration(usrCtx, rpub, username, serverId)` -> `rrec` (`OPAQUE_REGISTRATION_RECORD_LEN`, 192 bytes), where `rpub` must be `OPAQUE_REGISTER_PUBLIC_LEN` (64 bytes). Pass `export_key = NULL` (Arkfile never uses the OPAQUE export key; `opaque.c` skips computing it when `NULL`, avoiding unused key material and avoiding the 32-vs-64-byte buffer bug).
- `opaqueCreateCredentialRequest(password)` -> `(sec, pub)` where `pub` is `OPAQUE_USER_SESSION_PUBLIC_LEN` (96 bytes) and `sec` is `OPAQUE_USER_SESSION_SECRET_LEN + pwdLen` (`226 + pwdLen` bytes).
- `opaqueRecoverCredentials(resp, sec, username, serverId)` -> `(sk, authU)` where `resp` must be `OPAQUE_SERVER_SESSION_LEN` (320 bytes), `sk` is `OPAQUE_SHARED_SECRETBYTES` (64 bytes), `authU` is `crypto_auth_hmacsha512_BYTES` (64 bytes), the OPAQUE context parameter is the exact UTF-8 bytes of `"arkfile_auth"`, and `export_key = NULL`.

Also expose `ed25519VerifyDetached(signature, message, publicKey): Boolean` backed by libsodium's `crypto_sign_verify_detached` for verifying signed APK update manifests.

Mandatory native safety rules:

- Call `sodium_init()` in `JNI_OnLoad` (and guard lazily in every native entry point); abort/throw if `sodium_init() < 0`.
- Scrub every native copy of `password`, `usrCtx`, `sec`, `sk`, and Argon2 outputs with `sodium_memzero` before freeing/releasing JNI byte arrays (including on error paths).
- Never copy `usrCtx` or `sec` to disk or logs; both embed plaintext password bytes until step 2 completes. Scrub them in Kotlin (`fill(0)`) in a `finally` block immediately after step 2.

### Out-of-Tree Native Build Layout (Never Mutate `vendor_c/`)

`scripts/setup/build-libopaque.sh` builds host Linux `.a` files in-tree inside `vendor_c/` and runs `make clean` / `make distclean` there. Building Android NDK or Kotlin desktop native libraries inside `vendor_c/` would clobber Go server/CLI build artifacts and break `dev-reset.sh`, `go test ./...`, and `build-client.sh`.

Follow the out-of-tree staging pattern already proven in `scripts/setup/build-libopaque-wasm.sh` (lines 306-341):

- Keep `vendor_c/` as the read-only source of truth pinned by commit in `scripts/setup/build-config.sh`.
- Add `clients/kotlin/native/CMakeLists.txt` and `clients/kotlin/native/arkfile_jni.c`, plus a build script `scripts/setup/build-kotlin-native.sh` (invocable standalone or via a Gradle task).
- Stage clean copies of the pinned `vendor_c/` commits into `${ARKFILE_KOTLIN_BUILD_DIR:-/tmp/arkfile-kotlin-build}/native/<target>/` (verifying `git rev-parse HEAD` against `build-config.sh` pins and writing a build stamp so unchanged rebuilds are cached).
- When building `libsodium` for Android, **always set `LIBSODIUM_FULL_BUILD=1`** (`vendor_c/jedisct1/libsodium/dist-build/android-build.sh` defaults to `--enable-minimal`, which strips `ristretto255` and breaks `libopaque`/`liboprf`). Do NOT pass `--disable-pie` when compiling for shared libraries (Android `.so` requires `-fPIC`), and always link Android `.so` binaries with **`-Wl,-z,max-page-size=16384`** (required for 16 KB ELF page-size arm64 devices on Android 15+).
- Compile only the C sources single-server OPAQUE actually requires: `vendor_c/stef/liboprf/src/{oprf.c, toprf.c, utils.c}` and `vendor_c/stef/libopaque/src/{opaque.c, common.c}` with `-DHAVE_SODIUM_HKDF=1` and a staged `oprf/{oprf.h, toprf.h}` include directory. Single-server OPAQUE does not use `noise_xk` or threshold DKG (`dkg.c`, `tp-dkg.c`, `stp-dkg.c`, `toprf-update.c`), which keeps the CMake build small and portable.
- Keep native builds per-OS (Android cross-built with the Android NDK; Linux, Windows, and Mac each built natively on that OS, matching `docs/wip/cli-builder.md`). For the future Windows target, note that `oprf.c` / `toprf.c` include `<arpa/inet.h>` and `opaque.h` uses C99 VLA parameter syntax, so compile with MSYS2 MinGW-w64 or Clang (with a small `<winsock2.h>` header shim) rather than MSVC in C mode.
- `libfido2` is not built or linked for this app.

## Protocol, Wire Format, and Crypto Floor Contract

### Authentication, Sessions, and Single-Flight Refresh

- **Bearer auth only, cookies strictly disabled:** Login and refresh endpoints set browser session cookies (`__Host-arkfile-token`, `__Host-arkfile-refresh`, `__Host-arkfile-csrf`) AND return `token`, `refresh_token`, `expires_at`, and `session_expires_at` in JSON. If the Kotlin HTTP client (Ktor or OkHttp) installs a cookie jar, sending `__Host-arkfile-token` back causes `CSRFMiddleware` (`handlers/middleware.go:594-642`) to reject every POST/PUT/DELETE with HTTP 403 `CSRF token missing`. Disable cookie storage completely. Authenticate strictly with `Authorization: Bearer <token>`, pass `{"refresh_token": "..."}` in the JSON body for `POST /api/refresh` and `POST /api/logout`, and send neither auth headers nor cookies to `/api/public/shares/*`.
- **Single-flight refresh lock (`Mutex`):** Refresh tokens rotate on every use, and presenting an already-rotated token triggers server-side reuse detection (`handlers/auth.go:76-82`) that immediately revokes ALL sessions and active JWTs for the account. Serialize all `POST /api/refresh` calls through one process-wide `Mutex` (mirroring `client/static/js/src/__tests__/refresh-lock.test.ts` and `cmd/arkfile-client/session_lock_unix.go`) so concurrent UI queries, foreground chunk transfers, and billing pollers can never race on a rotation.
- **Session lifetimes and transfer grace window:** Access tokens live 30 minutes; refresh proactively around 25 minutes (5-minute threshold), before each chunk transfer, and on HTTP 401. Server session families end after 6 hours idle or 24 hours from sign-in (`docs/wip/auto-logout.md`), with an in-flight transfer grace window up to 36 hours (30 minutes quiet). Parse the JSON `error` code on every 401 (`session_idle`, `session_absolute`, `session_logged_out`), immediately clear local session and Account Key state, and surface the clear session-ended message.
- **Custom server URL and TLS policy:** Allow users to configure any HTTPS Arkfile origin (defaulting to the production instance or user-entered self-hosted URL). Reject insecure/cleartext HTTP and untrusted TLS certificates everywhere except explicit loopback (`localhost`, `127.0.0.1`, `::1`), matching `cli/tlspolicy/tlspolicy.go`.

### Compile-Time Floors and Validation Rules

- Embed `crypto/argon2id-params.json`, `crypto/chunking-params.json`, `crypto/password-requirements.json`, and `crypto/file-tags-params.json` directly from the repository root via a Gradle resource generation task so there is only one source of truth.
- Fetch `/api/config/opaque` (`server_id`, required for every OPAQUE transcript), `/api/config/argon2`, `/api/config/chunking`, `/api/config/password-requirements`, and `/api/config/file-tags`. Treat the non-OPAQUE config fetches as advisory and clamp every security parameter against the embedded compile-time floors (mirroring `client/static/js/src/crypto/floors.ts`) so a compromised server cannot downgrade Argon2id cost, chunk/AEAD sizes, or password minimums. For `specialCharacters`, allow narrowing only and reject widening.
- Enforce deterministic password validation matching `crypto/password_validation.go` (no zxcvbn, no strength scores, pass/fail length + character classes, plus `MaxPasswordBytes = 1024` UTF-8 cap before Argon2id) and username validation matching `utils/username_validator.go` (10-50 chars, `^[a-z0-9_\-.,]{10,50}$`, cannot begin or end with `.`, `,`, `-`, `_`).

### One Streaming Path and Exact Wire Invariants

There is exactly one upload encrypt/stream path and one download decrypt/stream path for the Kotlin client. Both process a single plaintext chunk (`plaintextChunkSizeBytes`, currently 16 MiB) at a time so a 6 GB file stays bounded in memory on a 3 GB RAM phone.

- **Key derivation:** Owner Account and Custom keys derive a 32-byte context salt via `SHA-256("arkfile-owner-kdf-v1" || 0x00 || context || 0x00 || publicSalt)` where `context` is `"account"` or `"custom"` (`crypto/key_derivation.go:128-143`), then run Argon2id with that 32-byte salt. Share keys run Argon2id directly with the share's random 32-byte salt.
- **Two-pass streaming upload over SAF:** Because `POST /api/uploads/init` requires `encrypted_sha256sum` before chunk 0 is uploaded, upload runs two sequential streaming passes over the source: Pass 1 streams plaintext to compute lowercase hex SHA-256 (rejecting 0-byte files per `cmd/arkfile-client/commands.go:465` and running the optional dedup check), and Pass 2 opens a fresh `InputStream` via `ContentResolver.openInputStream(uri)` (never copying the file into app cache!) to encrypt and upload 16 MiB chunks, verifying that the byte count read in Pass 2 matches Pass 1.
- **Client-minted UUID v4 and encrypted `total_size`:** Mint `file_id` as a strict canonical lowercase RFC 4122 UUID v4 (`handlers/uploads.go:126-133`). On HTTP 409 `file_id_conflict`, retry up to 3 times with a freshly minted UUID, fresh random 32-byte FEK, and re-encrypted envelope/metadata (`cmd/arkfile-client/commands.go:499-578`). Send `total_size` as the pre-padding encrypted stream size (`sum(chunkPlaintextLen + 28)` per `calculateTotalEncryptedSize` in `cmd/arkfile-client/crypto_utils.go:326`), NOT the plaintext file size.
- **Chunk format and retry:** Each encrypted chunk is `[12B nonce][ciphertext][16B tag]` with AAD `BuildChunkAAD(fileID, chunkIndex, totalChunks)` (`[4B BE len][fileID][8B BE chunkIndex][8B BE totalChunks]`). Upload as raw `application/octet-stream` to `POST /api/uploads/:sessionId/chunks/:chunkNumber` with header `X-Chunk-Hash: <lowercase hex SHA-256 of encrypted chunk>`. Retry individual chunk uploads and downloads on transient failures (network errors, HTTP 408/429/5xx) with exponential backoff (matching `cmd/arkfile-client/transfer_retry.go`); abort immediately on 401 session-ended, 409 `chunk_hash_conflict`, or AEAD failures.
- **Owner FEK envelope v2 vs metadata field nonce splitting:** The owner FEK envelope is base64 of `[35B header (0x02 | keyType 0x01/0x02 | kdfProfile 0x01 | 32B publicSalt)][12B nonce][32B ciphertext][16B tag]` (95 bytes raw) with AAD `BuildFEKEnvelopeAAD(fileID, header)`. In contrast, owner metadata fields (`encrypted_filename`, `encrypted_sha256sum`, `encrypted_password_hint`, `encrypted_tags`) split out the 12-byte nonce into `*_nonce` (base64) while `encrypted_*` is base64 of `[ciphertext][16B tag]` without the nonce prefix (`cmd/arkfile-client/crypto_utils.go:100-166`), using AAD `BuildMetadataFieldAAD(fileID, fieldLabel, ownerUsername)`. Omit optional `encrypted_password_hint`/`password_hint_nonce` and `encrypted_tags`/`tags_nonce` on upload init when empty; on `PUT /api/files/:fileId/tags` after removing the final tag, send both tag fields as empty strings.
- **Share envelope and ticket rotation:** Share envelope ciphertext is base64 of `[12B nonce][ciphertext][16B tag]` with AAD equal to raw UTF-8 concatenation `share_id + file_id` (no 4-byte length prefixes; see `crypto/testdata/crypto-conformance-v2.json:62`). After decrypting a share envelope, MUST validate its embedded `kdf_params` against the compile-time Argon2id floors (rejecting `weak_kdf_encrypted_envelope_base64`). Exchange `download_token` at `POST /api/public/shares/:id/ticket` and send `X-Share-Ticket` on metadata/chunk fetches, transparently refreshing the ticket on 403 mid-download (`client/static/js/src/shares/share-ticket.ts`). Accept either a pasted full `/shared/<id>` URL or a bare share ID (warning/confirming if the URL host differs from the configured server).
- **Download integrity and safe filenames:** Stream decrypted chunks directly to the destination SAF URI / file while hashing plaintext SHA-256 inline. If the final computed SHA-256 mismatches the expected decrypted digest, delete or abandon the partial output when possible, never report success, and show a prominent integrity mismatch error. Sanitize downloaded/exported filenames and resolve directory collisions case-insensitively without silently overwriting existing files (matching `cmd/arkfile-client/output_basename.go`, max 200 bytes).

### Full Feature Parity Scope

To reach full parity with `arkfile-client` and the web frontend (excluding hardware security key FIDO2/WebAuthn and admin-only endpoints), the app covers:

- **Auth & account lifecycle:** OPAQUE register (sending `account_kdf_salt` 32B canonical base64 and `account_kdf_profile: 1`), OPAQUE login, OPAQUE re-registration ceremony (`409 account_requires_reregistration`, test-decrypting the Account-Key `verifier` before re-binding `/api/opaque/reregister/*`), pending-approval state (`is_approved = false`, keeping `/api/user/contact-info` and `/api/auth/crypto-metadata` accessible), logout, and revoke-all (`POST /api/auth/revoke-all`).
- **MFA lifecycle & recovery:** First-time TOTP setup (displaying secret + QR code and 10 backup codes), TOTP login, emergency backup code login (Path A: `POST /api/mfa/auth` with `is_backup: true`), lost-factor replacement (Path B: `/api/mfa/recover-with-backup-code` -> `/api/mfa/reset`), MFA management (`GET /api/mfa/credentials`, adding TOTP as a second factor via `/api/mfa/credentials/totp/add`, removing a factor with force-logout warning, regenerating backup codes), and routing strictly from `mfa_methods` / `pending_mfa_method` (if an existing account has only WebAuthn enrolled, clearly explain that security keys are unsupported in the app and guide the user to Path A backup code or adding TOTP via web/`arkfile-client`).
- **Vault operations:** Cursor-paginated file list (`GET /api/files?limit=&cursor=`), metadata display, single and batch streaming upload (account password and custom password + optional encrypted hint), client-side plaintext SHA-256 upload deduplication (verified against `/api/files/:id/meta`, with override), single and batch streaming download (including prompting for custom passwords and displaying decrypted hints), file delete, and owner file tags (add comma-separated list, single remove/replace, `expected_revision` / `409 tags_revision_conflict` handling, client-side AND tag filtering).
- **Sharing:** Create share (`GET /api/files/:fileId/envelope`, `POST /api/shares`, copy link + password safely), list shares (`GET /api/shares`), revoke share (`POST /api/shares/:id/revoke`), and anonymous share receive without logging in.
- **Backups & local verification:** Single and batch `.arkbackup` v2 export (`GET /api/files/:fileId/export`), offline `.arkbackup` v2 inspection and decryption (single and folder batch grouped by Account Key, matching `cmd/arkfile-client/offline_decrypt.go`), `arkbackup-manifest.json` create and verify (`cmd/arkfile-client/backup_manifest.go`), and the local streaming **Verify File** SHA-256 tool (`client/static/js/src/files/verify-file.ts`).
- **Account info, billing, and subscriptions:** Server-encrypted contact info (`GET/PUT/DELETE /api/user/contact-info`, labeled honestly as server-encrypted for operator communication), admin contacts (`GET /api/admin-contacts`), PAYG balance/usage (`GET /api/credits`), manual OOB top-up info (`GET /api/oob-payments` PayNym/Monero display), Bitcart top-up invoice creation and status polling (`POST /api/billing/invoice`, `GET /api/billing/invoice/:id`), and Subscription Bridge plans/status/checkout/portal (`/api/subscriptions/*`). External checkout and portal URLs open via Android `Intent.ACTION_VIEW` (or OS browser on desktop) -- never in an embedded WebView and with zero payment SDKs.

## Account Key Lifecycle and Optional Dual Unlock Shortcut

### Default Lifecycle (Memory-Only)

By default, the account password is never persisted, and the derived Account Key and refresh token live in process memory only. Zeroing JVM/Android byte arrays is best-effort because the garbage collector may copy buffers; treat this as the same class of limit the browser client already accepts.

Default lock triggers:

- **Backgrounding:** Lock and wipe the in-memory Account Key whenever the app moves to the background (`ProcessLifecycleOwner` `ON_STOP`), with three explicit operational exceptions so normal workflows do not break:
  1. Screen rotation / configuration changes (store the key in an application-scoped singleton / service, never inside an `Activity`, so rotation does not trigger lock).
  2. Explicit system file-picker handoff (`ACTION_OPEN_DOCUMENT` / `ACTION_CREATE_DOCUMENT` / `ACTION_OPEN_DOCUMENT_TREE`), where Android temporarily backgrounds the app while the user selects a file or folder.
  3. Bounded external-browser payment hold while watching an active Bitcart or Subscription Bridge checkout (matching `idleLockHoldUntil` in `client/static/js/src/crypto/account-key-cache.ts:145`, capped at 2 hours and bounded by the fixed TTL).
  4. An already-running foreground upload/download continues to completion using its in-flight per-file FEK even if the UI locks the Account Key while backgrounded; any remaining queued batch files that still require the Account Key pause cleanly until unlocked.
- **Inactivity idle timer and TTL (matching the web frontend and CLI agent):** Default to a **15-minute inactivity auto-lock** and a **1-to-4-hour configurable TTL** (default 1 hour), matching `client/static/js/src/crypto/account-key-cache.ts:112-121` and `cmd/arkfile-client/agent.go:32-34`. (Note: 6 hours is the *server session idle timeout*, not the frontend Account Key cache timeout; the Account Key timer must never outlive the server's 6h idle / 24h absolute session caps.)
- **Explicit lock, logout, revoke-all, session end, or process death:** Immediately wipe the Account Key (and clear the refresh token on logout/revoke-all/session-end).

### Optional Combined Dual Unlock Shortcut (Opt-In, Bounded to Active Server Session <= 24h)

Because re-entering a 15+ character account password and TOTP code after every background trip is painful on a phone, users may optionally opt in (disabled by default) to a **Combined Dual Unlock Shortcut** after completing full OPAQUE + TOTP login. It never extends the server's 6-hour idle or 24-hour absolute session caps; once the server ends the session family, full OPAQUE + TOTP login is required again.

Cryptographic and lifecycle contract:

1. **Separate long PIN:** The user sets a dedicated app unlock PIN distinct from the OS lock-screen PIN (not a 4-6 digit numeric PIN; exact minimum length/policy confirmed in Remaining Open Questions).
2. **Inner wrap (PIN -> Argon2id -> AES-256-GCM):** Generate a fresh 32-byte random salt and derive a 32-byte wrapping key using `phc-winner-argon2` Argon2id at the compile-time floor (64 MiB, t=3, p=1) over a dedicated domain-separated context salt `SHA-256("arkfile-device-unlock-v1" || 0x00 || randomSalt)`. Never reuse `"account"` or `"custom"` contexts. Encrypt a serialized payload containing `{account_key, refresh_token, username, server_url, account_kdf_salt, account_kdf_profile, session_expires_at}` with AES-256-GCM whose AAD binds `(username, server_url, created_at_ms, expires_at_ms)` so editing side metadata cannot extend expiry or redirect the token.
3. **Outer wrap (Android Keystore AES-256-GCM):** Encrypt the inner ciphertext blob under a non-exportable Android Keystore AES-256-GCM key (`PURPOSE_ENCRYPT | PURPOSE_DECRYPT`, `BLOCK_MODE_GCM`, `ENCRYPTION_PADDING_NONE`, `setUnlockedDeviceRequired(true)`, preferring `setIsStrongBoxBacked(true)` with fallback to hardware TEE Keystore when StrongBox is absent). Because the Keystore key cannot be exported, copying app private storage off the device is insufficient to brute-force the long PIN offline.
4. **Attempt throttling and wipe:** Persist a failed-attempt counter alongside the wrapped blob; each failed unlock pays the full Argon2id cost, and reaching the attempt limit immediately wipes the wrapped blob, deletes the Keystore key alias, and forces full OPAQUE + TOTP login.
5. **Secrets never included:** Never store the account password, custom file passwords, or share passwords in this wrap. Custom-password files always prompt on use.
6. **Hard teardown:** Destroy the wrapped blob and delete the Keystore alias immediately on logout, revoke-all, server returning `session_idle` / `session_absolute` / `session_logged_out`, reaching `session_expires_at` (checked against both wall clock and monotonic `elapsedRealtime` so setting the phone clock backward cannot stretch the window), or disabling the toggle.

## Android Packaging, Hardening, and Development Workflow

### APK Packaging and Signing

- Build a self-signed release APK (`net.arkfile.app`, launcher label `Arkfile`, `minSdk = 28`, `targetSdk = 35`, `arm64-v8a` only; debug builds use `applicationIdSuffix = ".debug"` and may optionally include `x86_64` for local emulator testing).
- Users install via Android's "install unknown apps" permission. There is no Google Play listing, no Play App Signing, and no Google account in the release pipeline. Losing the release signing keystore prevents shipping in-place upgrades over existing installs, so treat the keystore as a critical operational secret with encrypted offline backups.

### Android Platform Hardening Checklist

- **`FLAG_SECURE`:** Set `WindowManager.LayoutParams.FLAG_SECURE` on sensitive screens (login, register, TOTP secret/QR, 10 backup codes, vault list, password/PIN prompts, share credentials) so screenshots, screen recordings, and Android Recents thumbnails do not leak secrets.
- **No cloud or ADB backups:** Set `android:allowBackup="false"` and strict `android:dataExtractionRules` / `android:fullBackupContent` so Google Drive backup and `adb backup` never extract session files or Dual Unlock blobs.
- **Network Security Config & dev loopback:** Block cleartext traffic globally in `network_security_config.xml`. Allow untrusted/local TLS strictly for loopback (`127.0.0.1`, `::1`, `localhost`). During local development against `https://localhost:8443` after `dev-reset.sh`, run `adb reverse tcp:8443 tcp:8443` so the physical phone or emulator connects to `https://127.0.0.1:8443` without weakening TLS policy for `10.0.2.2`.
- **Clipboard hygiene:** Mark sensitive clipboard copies (TOTP secrets, backup codes, share URLs/passwords, SHA-256 digests) with `ClipDescription.EXTRA_IS_SENSITIVE = true` on Android 13+ (API 33+) so keyboard overlays hide them.
- **Zero-PII logging & R8 keep rules:** Never log usernames, filenames, tags, password hints, keys, tokens, share IDs, or hashes to `Logcat` (even in debug paths -- log only stages, chunk counts, byte counts, durations, and HTTP status codes, matching `streaming-download.ts`). Add explicit R8/ProGuard keep rules for every Kotlin class and method bound via JNI so release minification cannot break native symbol resolution.
- **Foreground transfer service (Android 13-15):** Run multi-gigabyte uploads, downloads, and exports inside a Foreground Service with `POST_NOTIFICATIONS` support on API 33+, progress notifications, and a Cancel action (cancelling an upload invokes `DELETE /api/uploads/:sessionId` to clean up server state). Account for Android 15's 6-hour per-24h cap on `FOREGROUND_SERVICE_DATA_SYNC` when handling very long mobile transfers (design clean pause/resume or chunked restart boundaries where needed).

### Signed Sideload In-App Updater

- **Opt-out (default on) with zero telemetry:** Periodic update checks are enabled by default with a prominent toggle in Settings (and a manual "Check for Updates" button) so self-hosted or Tor-routed users can disable outbound checks cleanly. The check performs a minimal static HTTP GET carrying no auth headers, no cookies, no install ID, no device/OS fingerprint, no username, and no vault server URL.
- **Ed25519 manifest verification + APK SHA-256:** Fetch a static `release.json` manifest (containing `versionCode`, `versionName`, `apk_url`, `apk_sha256`, `min_sdk`, `release_notes`) plus its detached Ed25519 signature (`release.json.sig`) signed by an offline Arkfile Open Source Project release key whose public key is pinned inside the app binary. Verify the signature via libsodium's `crypto_sign_verify_detached` (already in `libarkfile_native`), enforce monotonic `versionCode` (anti-downgrade), stream-download the APK to app cache, verify its exact `apk_sha256`, and only then launch Android's package installer (`ACTION_INSTALL_PACKAGE` with `REQUEST_INSTALL_PACKAGES`; Android itself also enforces that the APK signing certificate matches `net.arkfile.app`).

### Development Workflow Without Android Studio

- All build, test, and device workflows run from the command line inside Cursor/VSCodium using a pinned JDK (JDK 21 LTS), Gradle wrapper (`gradle/libs.versions.toml` + `gradle-wrapper.properties`), Android command-line tools (`sdkmanager`), Android platform/build-tools/platform-tools (`platforms;android-35`, `build-tools;35.0.0`), pinned NDK (r28+), and CMake. Android Studio is not required.
- For rapid UI iteration without waiting on APK deploys, run `./gradlew :desktopApp:run` on Linux X11/XLibre resized to a phone viewport to preview shared Compose screens in seconds, and use `./gradlew :androidApp:assembleDebug && adb install -r ...` + `adb reverse tcp:8443 tcp:8443` + `adb logcat` on a real `arm64-v8a` phone for Android-specific SAF, Foreground Service, and Keystore verification. IntelliJ IDEA Community Edition remains strictly optional.

## Theme, Layout, and Desktop Targets

### Visual Consistency With the Web Frontend

Compose will not imitate GTK, AppKit, or Win32; it follows the Arkfile website's visual identity. Map the CSS tokens in `client/static/css/styles.css` directly into one shared Compose theme:

- Surfaces: `--depth-1` (`#060d1a`), `--depth-2` (`#0a1628`), `--depth-3` (`#112240`), `--depth-4` (`#1e3a5f`).
- Controls and secondary text: `--current-1` (`#2d6a9f`), `--current-2` (`#4a9fd4`), `--foam-1` (`#cce7ff`), `--foam-2` (`#8ab8d8`).
- Accents and status: `--biolum` (`#00d4aa`), `--phosphor` (`#f0a500`), `--coral` (`#e05c5c`), `--salt` (`#ffffff`).
- Control proportions: match `--control-height` (`2.25rem` / ~36 dp on desktop, touch-comfortable >= 44-48 dp on Android) and monospace formatting for SHA-256 digests, file IDs, and backup codes.

Shared screens provide two responsive layouts over shared components: a compact layout for phone viewports and an expanded layout for desktop windows.

### Desktop Platforms (After Android)

Keep platform differences strictly behind thin `expect`/`actual` boundaries: loading `libarkfile_native`, file/folder pickers, streaming file I/O, external browser launch, per-user session/settings paths, and optional OS secure storage.

- **Linux (second platform):** Target **X11 / XLibre exclusively** (no Wayland requirement). Compose Desktop runs on AWT + Skiko (Skia), which uses X11 natively. Test early on the developer's X11/XLibre host under both GLX hardware rendering and Skiko software fallback (`SKIKO_RENDER_API=SOFTWARE`), and confirm clipboard, HiDPI scaling, and file dialogs work cleanly without assuming Wayland or GNOME-only portals. Package initial releases as `.deb` and `.rpm` via `jpackage` (bundled minimal `jlink` runtime + `libarkfile_native.so`) and wrap the `jpackage` app-image as an AppImage with `appimagetool`.
- **Windows (third platform):** Build `arkfile_native.dll` natively on Windows (MSYS2 MinGW-w64 or Clang via CMake) and package via `jpackage`. Initial release ships unsigned with published SHA-256 checksums and detached Ed25519 signatures (documenting the expected Windows SmartScreen "More info -> Run anyway" prompt); paid Authenticode code signing is deferred.
- **Mac (fourth platform):** Build `libarkfile_native.dylib` natively on Apple Silicon (and optionally Intel if needed) and package via `jpackage`. Note that macOS Apple Silicon kills completely unsigned `arm64` binaries with `SIGKILL`, so unsigned initial releases must still be **ad-hoc signed** (`codesign --force --deep --sign -`) alongside published SHA-256 checksums and detached Ed25519 signatures, documenting quarantine removal (`xattr -dr com.apple.quarantine`) for sideloaded users; Apple Developer ID ($99/yr) notarization is deferred.

## Implementation Milestones and Verification Ladder

### Ordered Milestones

1. **Prerequisites and Repo Isolation:** Fix the `auth/opaque_client.go` `export_key` buffer overflow + C-heap scrubbing, add `sodium_init()`, vendor and pin `phc-winner-argon2` under `vendor_c/`, and add `syft` excludes + `.gitignore` rules for `clients/kotlin/`.
2. **Native C/JNI Layer and Kotlin Crypto Core:** Scaffold `clients/kotlin/` (`shared`, `androidApp`, `desktopApp`, `native`), implement `scripts/setup/build-kotlin-native.sh` + `CMakeLists.txt` + `arkfile_jni.c` for Linux host and Android `arm64-v8a`, embed `crypto/*.json` floors, implement Argon2id/OPAQUE/AAD/owner-envelope/metadata/chunk/share-envelope/tag/password/username crypto core in `shared`, and pass 100% of conformance fixtures plus live OPAQUE/vault round-trip against `dev-reset.sh`.
3. **Core Vault Android APK:** Implement the Compose theme, server URL config, Bearer HTTP client (no cookies, single-flight refresh `Mutex`), OPAQUE register/login/re-registration, pending-approval handling, TOTP setup/login, cursor-paginated file list, two-pass SAF streaming upload/download via Foreground Service (both account and custom passwords + hints), share create/list/revoke/receive, revoke-all, Android hardening (`FLAG_SECURE`, `allowBackup=false`, `network_security_config.xml`, R8 keep rules), and constrained-RAM multi-GB transfer proof.
4. **Full Feature Parity on Android:** Add owner file tags (including optimistic concurrency and client-side AND filtering), batch upload/download/export with collision-safe sanitized filenames, upload deduplication, `.arkbackup` v2 export + offline decrypt + `arkbackup-manifest.json`, local Verify File tool, full MFA management + Path A/B backup-code recovery + WebAuthn-only account guidance, contact info, and PAYG/Bitcart/OOB/Subscriptions via external browser.
5. **Dual Unlock Shortcut and Signed Updater on Android:** Implement the opt-in Combined Dual Unlock Shortcut (Long PIN + Android Keystore/StrongBox, <= 24h session cap) and the opt-out Ed25519-verified in-app APK update checker.
6. **Desktop Targets:** Ship and verify Linux X11/XLibre (`.deb`/`.rpm`/AppImage), then Windows, then macOS.

### Four-Layer Verification Ladder

1. **Shared JVM Crypto & Format Unit Tests (`./gradlew :shared:jvmTest`):** Directly load repo-root `crypto/testdata/argon2-conformance-vectors.json` and `crypto/testdata/crypto-conformance-v2.json` (including `weak_kdf_encrypted_envelope_base64`), plus tests for compile-time floor clamping, username/password/tag validation, `.arkbackup` v2 parsing/validation, `arkbackup-manifest.json`, and `output_basename` filename sanitization. Runs in seconds without an Android device.
2. **Native JNI End-to-End Protocol Interop (Linux JVM + live server):** Run automated Kotlin JVM integration tests backed by Linux `libarkfile_native.so` against a local Arkfile instance (after `dev-reset.sh`), exercising OPAQUE register/login/re-registration, TOTP, upload/download, custom password + hint, tags, shares, export/offline decrypt, and cross-client round-trip verification with `/opt/arkfile/bin/arkfile-client`.
3. **Android On-Device Instrumentation & Security Tests (`adb`):** Verify SAF two-pass streaming upload and download, Foreground Service survival while backgrounded/screen-off, background-lock exceptions (rotation, SAF picker, payment hold), Dual Unlock Shortcut wrap/unwrap/tamper/attempt-limit/expiry, `FLAG_SECURE`, and Ed25519 manifest + APK SHA-256 update checks on a real `arm64-v8a` phone.
4. **Constrained-Memory Multi-GB Transfer Proof:** Upload and download a multi-gigabyte file (targeting the 6 GB file on a 3 GB RAM phone class) while sampling `adb shell dumpsys meminfo net.arkfile.app` to confirm peak memory remains bounded near one 16 MiB chunk buffer plus transient Argon2id derivation and never grows with file size.

## What This Project Does Not Do

It does not replace `arkfile-client` or the web frontend. It does not introduce a new OPAQUE implementation, a new owner envelope version, a new chunk size, or a second source of truth for cryptographic parameters. It does not extend server session lifetimes (6h idle / 24h absolute). It does not persist the account password, custom file passwords, or share passwords on disk. It does not enroll or authenticate hardware security keys (WebAuthn/FIDO2). It does not ship iOS, Google Play Store releases, Play Services, embedded WebViews/browsers, Wayland support on Linux, or require Android Studio.

## Remaining Open Questions

1. **Signed update manifest URL:** What exact static HTTPS host and path (for example under `arkfile.net` or a dedicated release host controlled by the Arkfile Open Source Project) will serve `release.json` and `release.json.sig`, and where will the offline Ed25519 release signing key be stored?
2. **Optional Dual Unlock Shortcut Long PIN policy:** What minimum length, character requirement, and failed-attempt wipe limit should be enforced for the optional Long PIN (recommendation: minimum 12 characters with at least 2 character classes, and wipe the wrapped blob + Keystore alias after 5 failed attempts)?
3. **Desktop Dual Unlock parity:** Should Linux, Windows, and Mac desktop builds also implement the optional Dual Unlock Shortcut (via OS Secret Service / DPAPI / Keychain) in a later pass, or keep desktops strictly memory-only while `arkfile-client` covers local agent workflows?
4. **Linux desktop file chooser polish:** Is standard AWT/Swing file picking acceptable for the first Linux X11/XLibre release, or should a native X11-friendly file dialog wrapper be prioritized before calling Linux done?
