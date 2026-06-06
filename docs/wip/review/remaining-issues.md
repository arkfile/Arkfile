# Arkfile Open Security Issues

This document is a code-verified inventory of priority security issues that are still open in Arkfile as of 2026-06-03. Every entry below was confirmed by reading the live source tree at the time. It is intended as the working baseline for planning future remediation sessions.

Issues here are grouped by app-functionality and by privacy/security concept. Each issue lists a plain-language title, the concrete file location where it lives, what it is, why it matters, and a rough effort note.

---

## 1. Server-Side Metadata and Privacy Leakage

Arkfile's central promise (per `docs/AGENTS.md`) is that the server, and especially any third-party S3 storage backend, learns nothing about the nature of a user's data. These items are places where that promise is not fully kept today.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| File size leaks to the server before padding | `handlers/uploads.go` (server applies random padding to the last chunk) | Padding is applied server-side, so the server observes the true unpadded ciphertext size before padding. A client-side padding strategy would prevent the server from ever seeing the unpadded size. | Medium |
| Account key reused as the metadata encryption key (deferred by choice) | `crypto/file_operations.go` / metadata encrypt-decrypt paths | The same Account-KEK that wraps per-file FEKs also directly encrypts filename and SHA-256 metadata. There is no key domain separation (e.g. an HKDF-derived metadata subkey). A dedicated subkey would isolate the metadata-encryption role from the FEK-wrapping role. **Reviewed and consciously deferred (2026-06-03):** this is defense-in-depth hygiene, not an exploitable hole. It does not defend against a cracked Account Key, since breaking Argon2id already yields the master secret that both unwraps FEKs and decrypts metadata. The fix would also require a coordinated encrypted-envelope format change across the Go server, the TypeScript frontend, and the `arkfile-client` CLI for marginal benefit. Revisit when an OPAQUE/crypto-hardening session is already touching these paths. | Low-Medium |

---

## 2. File Transfer Integrity and Robustness

File content confidentiality is solid, and per-chunk tamper detection is now enforced at the AEAD layer (the chunk/FEK/metadata AAD binding has landed). The items below are the remaining integrity-adjacent and robustness gaps in the upload/download pipeline. Most are now lower-risk because the AEAD layer catches active tampering, but they remain real correctness or availability bugs, especially for the large-file-on-constrained-device use case that `docs/AGENTS.md` emphasizes.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| Divergent secondary copy detection on download (reframed 2026-06-05) | `handlers/downloads.go` (`DownloadFileChunk` -> `storage.Registry.GetObjectChunkWithFallback`) | Code-verified: the download path serves individual byte-range chunks, never the whole blob, so the recorded `stored_blob_sha256sum` (a hash of the entire padded S3 object) cannot be verified inline against a single chunk range without buffering the whole object, which would defeat the constrained-device streaming design. Content tampering on a divergent/corrupted secondary copy is already detected at the AEAD layer: per-chunk AES-GCM AAD binds (file_id, chunkIndex, totalChunks), so any altered chunk fails authentication on the client. The genuine residual gap is a structurally-valid-but-stale/truncated secondary copy, which should be closed by an out-of-band integrity-scrub job (the admin `verify-all` task already does HEAD-based size verification and is the natural home for a deeper hash scrub). The original "verify the served blob inline on the fallback path" framing is not implementable as written. | Medium (scrub job) |
| In-process upload hash state lost on restart | `handlers/uploads.go` (`streamingHashStates` / `storedBlobHashStates` in-memory maps) | Code-verified: the per-session SHA-256 hasher state lives only in process memory and `CompleteUpload` hard-fails with "no streaming state found" if the maps are empty, so a mid-upload restart forces a full re-upload. Note the cheaper fix: per-chunk SHA-256 is already durably persisted in `upload_chunks.chunk_hash` and every chunk is already stored as an S3 part, so the whole-file `encrypted_file_sha256sum` / `stored_blob_sha256sum` can be recomputed at `CompleteUpload` time by streaming the already-stored parts instead of failing. This makes restart-resilience a recovery path rather than a new hasher-state persistence subsystem (avoid serializing Go's internal digest state). | Medium |
| Streaming download writes plaintext to disk before hash verification | `client/static/js/src/files/streaming-download.ts` / `sw-streaming-download.ts` (path corrected 2026-06-05) | Code-verified: on the Service Worker path the plaintext is hashed inline (`hasher.update`) and compared at `finalizeCompletion`, but the browser's download manager writes to disk in parallel, so the end-of-file hash result arrives after the file is on disk; a mismatch is reported via `hashVerification: 'mismatch'`, never thrown (by design). This is inherent to true streaming-to-disk on a constrained device. The realistic improvement is surfacing the mismatch prominently in the UI (today it is only a `console.warn`), not changing the streaming model. | Medium |
| Blob-fallback download path performs no end-of-file hash check | `client/static/js/src/files/streaming-download.ts` (Blob fallback when Service Worker is unavailable; path corrected 2026-06-05) | RESOLVED 2026-06-05. The Blob fallback (`streamDecryptedChunks`) previously returned `{ blobUrl }` with no hashing at all, unlike the SW path. It now hashes plaintext incrementally as chunks arrive (no extra memory) and returns a `hashVerification` field consistent with the SW path; a mismatch is surfaced to the caller and logged with the same PII-free message. Covered by `__tests__/streaming-download.test.ts`. | Done |
| Background replication is uncancellable | `handlers/uploads.go` (`replicateToSecondary`) | RESOLVED 2026-06-05. Upload replication previously ran in a detached `go func()` with `context.Background()`, invisible to the admin task system. It is now submitted through the existing `TaskRunner` as a `copy-file` task (admin_username marker `system-replication`), so each replication is a tracked, attributable `admin_tasks` row with built-in per-task cancellation. New admin surface: `list-tasks` (see running/recent tasks) and `cancel-all-tasks --type copy|verify|all` (the per-task `cancel-task --task-id` still works). Automatic replication is shown as its own origin in `list-tasks` but cancelled under the `copy` category, matching how a non-developer admin thinks about "copies". | Done |

---

## 3. OPAQUE Protocol Correctness

**All items in this section are RESOLVED as of 2026-06-05** (see "Resolved 2026-06-05" below). The OPAQUE primitives were already sound; this session completed the remaining correctness and hygiene items: the server public key is no longer stored independently (libopaque derives it from the private key), the server identity (idS) is now bound to the deployment FQDN instead of a hardcoded "server" literal, and the CGO key-material buffers are scrubbed after use. No OPAQUE-path items remain open.

---


## 4. Account and Identity Hygiene

Smaller correctness items around how accounts and the CLI clients handle identity and credential material.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| No Unicode normalization on usernames | `utils/username_validator.go` and username comparison sites | Username comparisons are byte-wise with no Unicode normalization or case-folding policy. Visually identical usernames with different byte encodings are treated as distinct, which can cause confusion and impersonation-adjacent edge cases. | Low-Medium |
| CLI credential and flag handling gaps | `cmd/arkfile-client/`, `cmd/arkfile-admin/` | Missing `--password-stdin` / `--account-key-file` flags create asymmetric stdin handling; the admin client returns the password as an immutable Go string that cannot be zeroed; and the initial session-file write is non-atomic (an interrupt during first login can leave a partial file). These are cross-binary consistency and memory-hygiene items. | Medium |

---

## 5. Anonymous Sharing Residuals

The major sharing issues (access-count race, per-share rate limiting, revoked-reason leakage) have been resolved. These residual items remain.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| Origin-header trust in share URL construction | `handlers/file_shares.go` (share URL construction) | RESOLVED 2026-06-06. Share URL construction no longer uses the client-supplied Origin header. It now uses configured `BASE_URL` when available, fails closed in production if `BASE_URL` is missing, and only falls back to request host in non-production/local contexts. Covered by focused handler tests asserting a hostile Origin is not reflected. | Done |
| Daily-rotating EntityID resets the rate-limit budget | `logging/entity_id.go` (day-bucketed HMAC) | The anonymous EntityID rotates daily, so an attacker's per-EntityID rate-limit budget resets each day and can be multiplied by waiting out the rotation window. The rotation period is a privacy-vs-abuse tradeoff worth revisiting. | Medium |
| Share access-attempts table grows unbounded | `handlers/rate_limiting.go` / `database/unified_schema.sql` (`share_access_attempts`) | RESOLVED 2026-06-06. The share/auth access-attempt table now has a 30-day retention window enforced by a throttled opportunistic prune in the rate-limit helper path. Existing `idx_share_access_cleanup` supports this cleanup. Covered by focused handler tests for pruning and throttle behavior. | Done |

---

## 6. Infrastructure and Host Hardening

Host- and build-level hardening items. These were intentionally deferred from earlier hardening work and remain open.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| Weak or unpinned dependency acquisition | `scripts/setup/` and deploy scripts | SeaweedFS integrity is verified with MD5; rqlite is built/pulled without a pinned commit or tag. Both should use SHA-256 and a pinned version respectively. | Low-Medium |
| No vulnerability scanning or SBOM in the build | `scripts/setup/build.sh` and deploy scripts | The build does not run `govulncheck` or `bun audit`, and emits no SBOM. Adding these (failing on high-severity findings) closes a supply-chain visibility gap. | Low-Medium |

### Cross-platform note for server-side hardening work

The primary server OS targets for now are Debian-derivatives and RHEL-derivatives running systemd, and that is where hardening effort should be focused first. However, we want to stay cognizant of a likely future need to deploy to and harden for FreeBSD, OpenBSD, and Alpine Linux. When touching host-hardening code, prefer changes that do not assume Linux or systemd exclusively, and fold in easy cross-platform wins opportunistically. Two concrete touchpoints to keep in mind:

- The user-secret master key memory-hardening (mlock, MADV_DONTDUMP, PR_SET_DUMPABLE) is Linux-specific and already lives behind platform-split files (`crypto/user_secret_master_linux.go` and `crypto/user_secret_master_other.go`). When extending it, provide equivalent protections on BSD (mlock / madvise are available) and fail gracefully where a primitive is unavailable, rather than assuming Linux.
- Alpine (OpenRC) and the BSDs (rc.d) do not use systemd, so host-hardening that lives in `.service` files has no effect there. Where a hardening control matters for security (core-dump suppression, loopback binding), prefer to also enforce it inside the application or its launch wrapper so the protection is not lost on a non-systemd host.

---

## 7. Code Hygiene and Technical Debt

Lower-stakes cleanups that reduce future friction, in line with the `docs/AGENTS.md` guidance to flag stubs, dead code, and placeholder comments.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| Build-tagged integration tests excluded from default test runs | `handlers/chunked_upload_integration_test.go` (and the 100MB variant) | The chunked-upload integration tests carry a build tag that excludes them from `go test ./...`, so the only end-to-end upload coverage is silently skipped by default. They should run in the standard suite or in CI. | Low |
| Driver-quirk workaround retained | rqlite base64 decode workaround in the data layer | A base64 "decode if needed" workaround papers over an rqlite driver quirk. Per greenfield policy this should be understood and removed rather than retained indefinitely. | Low-Medium |
| Minor dedup and constraint gaps | `handlers/files.go` (batch metadata does not dedup file IDs), upload-chunk uniqueness | Small data-hygiene items: the batch metadata request does not deduplicate its input IDs, and per-chunk uniqueness constraints are looser than they could be. | Low |
| Residual "for now" / placeholder comments | (OPAQUE server-identity placeholder resolved 2026-06-05) and similar | Any comment indicating a temporary or placeholder implementation should be flagged and resolved, per `docs/AGENTS.md`. The previously flagged OPAQUE idS "for now" comment is gone; this row remains as a standing reminder to flag any new placeholders. | Low |

---

## arkfile-client Build Portability

The primary build target for `arkfile-client` is Linux, but a core goal is to make it as easy as possible for users to compile the client on a wide range of systems and architectures, including the BSDs, macOS, and Windows, and across x86, ARM, and Apple Silicon. The main source of friction is the OPAQUE dependency, which is built through CGO and statically links libopaque and libsodium. Any work that touches the client build should:

- Avoid Linux-only assumptions in build scripts and in client code paths.
- Keep the CGO/static-link build documented and reproducible per platform, and verify cross-compilation where feasible (Go cross-compilation is straightforward, but CGO cross-compilation requires the right toolchain and a per-target libsodium build).
- Treat "the client compiles cleanly on this platform" as a first-class outcome when changing anything in the client build or its crypto dependencies.

When future sessions add platform-specific code to the client (for example, secure memory handling or session-file permissions), prefer build-tagged platform files (the pattern already used for the server-side user-secret master) so that each supported OS gets a correct implementation rather than a Linux assumption with a broken fallback.

---

## Recently Verified as Already Resolved

To prevent re-doing finished work, the following items are confirmed RESOLVED in the live code as of 2026-06-03. Older review documents may still imply these are open; they are not. Do not schedule remediation work for these without first re-reading the cited code.

- File-path AEAD binding (chunks, FEK envelope, metadata): implemented in `crypto/aad.go` and wired through the Go, TypeScript, and CLI encrypt/decrypt paths. Chunk reorder, truncation, cross-file chunk swap, and cross-file FEK swap are now detected at the AEAD layer.
- Admin route group enforces TOTP: `handlers/route_config.go` wires `RequireFullJWT` + `RequireTOTP` + `AdminMiddleware` onto the admin group and the dev-test group.
- Localhost-only authorization gate hardened: `handlers/middleware.go` uses `peerAddrIsLoopback` (kernel transport peer) for authz; `c.RealIP()` is explicitly deprecated for authorization. Bootstrap handlers use the same primitive.
- User-secret key store moved off the shared system-keys table: `crypto/user_secret_master.go` loads a separate on-disk master and applies mlock / MADV_DONTDUMP / PR_SET_DUMPABLE.
- TOTP backup codes are hashed, not encrypted: schema has `user_totp_backup_codes` with per-code hashes; the old encrypted-blob column is gone.
- Soft-delete preserves the financial audit trail: `users.deleted_at` exists and user deletion is a soft-delete; `credit_transactions.transaction_id` has a UNIQUE constraint; a persistent `billing_sweeps` table prevents duplicate daily sweeps.
- TOTP verification accepts an adjacent time window (skew of one) rather than zero.
- Anonymous-share access-count race, per-share rate limiting and timing protection, and revoked-reason leakage are all resolved.

### Resolved 2026-06-03
The following security and privacy gaps are confirmed RESOLVED in the live code as of 2026-06-03:
- **Owner username written to S3 object metadata**: Plaintext `"owner-username"` and `"session-id"` meta map keys removed from all multipart S3 upload calls.
- **Username and file identifier co-logged at INFO**: Replaced co-logging of plaintext usernames and file IDs in all handlers (e.g. upload, chunk download, and anonymous share creation/revocation handlers) with standalone IDs or EntityID-based markers where applicable.
- **rqlite binds all interfaces**: Restricted rqlite database's HTTP and Raft interfaces strictly to loopback binding (`127.0.0.1:4001` and `127.0.0.1:4002`) in systemd unit configs.
- **Missing process core-dump and related systemd hardening**: Applied systemd-level core-dump suppression via `LimitCORE=0` inline hardening to all primary service unit files (`arkfile.service`, `rqlite.service`, `caddy.service`, and `seaweedfs.service`) to fully harden memory-stored keys against physical inspection core leaks.
- **Client-supplied chunk hash never verified**: `UploadChunk` in `handlers/uploads.go` now compares the client `X-Chunk-Hash` header against the SHA-256 of the received encrypted chunk bytes and rejects a mismatch with HTTP 400 and stable error code `chunk_hash_mismatch` before the part is stored. This closes the former misleading no-op (the header was format-checked but never compared) and adds an early transport-integrity / corruption-detection check; per-chunk AEAD remains the authoritative tamper protection on download. Covered by `TestUploadChunk_RejectsChunkHashMismatch`.


### Resolved 2026-06-05
The entire OPAQUE-hardening area (former section 3) was completed and verified end-to-end (dev-reset + e2e + Playwright all passed). Confirmed RESOLVED in the live code as of 2026-06-05:
- **OPAQUE server public key generated independently**: Removed the independently generated `opaque_server_public_key`. libopaque derives the server public key from the private key during the protocol, so only the private key and OPRF seed are persisted. `auth/opaque.go` now exposes `GetServerPrivateKey()` (replacing `GetServerKeys()`), and the vestigial `opaque_server_keys.server_public_key` column is documented as such in `database/unified_schema.sql`.
- **OPAQUE server identity hardcoded as "server"**: idS is now bound to the deployment identity. `config.Server.Domain` resolves `ARKFILE_DOMAIN` -> the `BASE_URL` host (scheme/path/port stripped) -> `"localhost"`; `auth.OpaqueServerID()` is the single source of truth, served to clients via the new public `GET /api/config/opaque` endpoint. The browser WASM client (`opaque.ts`) and the Go CLIs (`arkfile-client`, `arkfile-admin`) fetch it and pass it into the parameterized `ClientFinalizeRegistration` / `ClientRecoverCredentials`. The "for now" placeholder comment is gone. `ValidateProductionConfig` now fails closed when a production deployment resolves to an empty/`localhost` domain.
  - **Operational requirement (breaking auth change):** `ARKFILE_DOMAIN` is now REQUIRED. `test-deploy.sh` / `prod-deploy.sh` write `ARKFILE_DOMAIN=${DOMAIN}` into `secrets.env`; `local-deploy.sh` writes `ARKFILE_DOMAIN=localhost`; `test-update.sh` / `prod-update.sh` hard-fail if it is missing (no backfill). Because idS is baked into each OPAQUE registration record, this required a greenfield reset (completed 2026-06-05).
- **CGO key-material buffer hygiene**: `auth/opaque_multi_step.go` now scrubs the sensitive C-heap copies (server secret, client record, user record) before they are freed in `StoreUserRecord`, and zeroes the unused server-side session key in `CreateCredentialResponse`, via `zeroCBytes`/`zeroBytes` helpers.
- Coverage added: `config` precedence + production domain-guard tests, `auth.OpaqueServerID` test, `handlers.GetOpaqueConfig` endpoint test, and `opaque-server-id.test.ts` (fetch/fallback). Go build, `go test ./config ./handlers ./auth`, `tsc --noEmit`, and the full `bun test` suite (365/0) all pass.

### Resolved 2026-06-05 (file-transfer robustness, part 1)
Two of the file-transfer-robustness items in Section 2 were completed and the remaining ones were re-verified and reframed against the live code:
- **Blob-fallback end-of-file SHA-256 verification**: the SW-unavailable Blob fallback in `client/static/js/src/files/streaming-download.ts` now hashes the decrypted plaintext incrementally and returns a `hashVerification` outcome consistent with the Service Worker path. Covered by `__tests__/streaming-download.test.ts`.
- **Background replication is now cancellable and observable**: upload replication is submitted through the existing admin `TaskRunner` as a `copy-file` task (origin marker `system-replication`) instead of a detached `context.Background()` goroutine. New admin commands `list-tasks` and `cancel-all-tasks --type copy|verify|all` were added; per-task `cancel-task --task-id` is unchanged.
- The download-fallback stored-blob verification item was reframed (not implementable inline; belongs in an out-of-band scrub job) and the in-process upload hash-state item was annotated with a cheaper recompute-from-stored-parts approach. See the Section 2 table for details.

### Resolved 2026-06-06 (pre-production sharing hardening)
The following anonymous-sharing residuals are confirmed RESOLVED in the live code as of 2026-06-06:
- **Origin-header trust in share URL construction**: `handlers/file_shares.go` now centralizes share URL base selection in `publicShareBaseURL`. It trims and uses configured `BASE_URL`, never reflects request `Origin`, fails closed in production without `BASE_URL`, and retains a request-host fallback only for non-production/local use. `CreateFileShare` resolves the base URL before writing the share record so a production URL misconfiguration cannot create a share and then fail to return a safe URL. `ListShares` uses the same helper. Covered by focused handler tests.
- **Unbounded `share_access_attempts` growth**: `handlers/rate_limiting.go` now prunes `share_access_attempts` rows older than 30 days through a throttled opportunistic cleanup path used by both share and auth rate-limit helpers. Covered by focused handler tests.
- **Streaming download hash-mismatch UI surfacing re-verified**: the open item saying Service Worker hash mismatches were only logged is stale. Live code already surfaces `hashVerification === 'mismatch'` via `showWarning(...)` in both owner download (`client/static/js/src/files/download.ts`) and anonymous share download (`client/static/js/src/shares/share-access.ts`) flows. If future UX work wants a stronger modal/interstitial, track that as UX polish rather than an unimplemented integrity warning.

If a future check finds any of the above regressed, treat that as a high-priority regression rather than a planned item.

---

## Where to Focus First (Prioritization)

Note (2026-06-03): the original top recommendations in this section have already been completed. Removing the plaintext owner username from S3 object metadata, binding rqlite to loopback, and applying systemd core-dump suppression are all done (see the "Resolved 2026-06-03" list). The unverified `X-Chunk-Hash` no-op is also resolved. And the HKDF-derived metadata subkey has been reviewed and consciously deferred (see section 1). The ranking below reflects what genuinely remains.

The most valuable remaining file-transfer-robustness work is now the in-process upload hash state lost on restart (so a mid-upload server restart does not force the client to re-upload the whole file), best done as a recompute-from-stored-parts recovery path at `CompleteUpload` time. Update (2026-06-05): the Blob-fallback end-of-file hash check and making background replication cancellable are now DONE (see "Resolved 2026-06-05 (file-transfer robustness, part 1)"). The Service-Worker plaintext-to-disk-before-hash item is inherent to streaming-to-disk; the realistic improvement there is surfacing a hash mismatch in the UI rather than only a console warning. The download-fallback stored-blob verification has been reframed: inline whole-blob verification is incompatible with chunked byte-range downloads, so it belongs in an out-of-band scrub job extending the admin `verify-all` task.

Update (2026-06-05): the focused OPAQUE-hardening session that was previously the second-priority area is now DONE (see "Resolved 2026-06-05"): the server public key is derived rather than stored, the server identity is bound to the deployment FQDN, and the CGO key-material buffers are scrubbed. It is no longer a remaining focus area.

The second area is the remaining privacy-leakage item that is not deferred: client-side padding so the server never observes the true unpadded ciphertext size. This is a Medium-effort change touching the upload pipeline and clients, so it is worth scheduling deliberately rather than squeezing in.

Everything else, including host/build supply-chain hardening (pinned dependencies, SHA-256 integrity, govulncheck/SBOM), the username normalization policy, the remaining sharing residual around the EntityID rotation tradeoff, and the code-hygiene cleanups, is genuinely useful but lower-leverage and can be slotted into later sessions once the areas above are in good shape.

---

# ADDITIONAL FINDINGS RELEVANT TO PROD DEPLOYMENT/UPGRADE FROM JUNE 6, 2026:

This section records a focused review of `scripts/prod-deploy.sh`, `scripts/prod-update.sh`, and the directly related build/setup/service templates (`scripts/setup/build-config.sh`, `scripts/setup/build.sh`, `scripts/setup/deploy.sh`, `scripts/setup/05-setup-seaweedfs.sh`, `scripts/setup/06-setup-rqlite-build.sh`, `Caddyfile.prod`, and the production systemd units). The scripts are directionally solid for a greenfield VPS deployment, especially around loopback binding for rqlite and SeaweedFS, disabling dev/test API flags, writing `BASE_URL`/`ARKFILE_DOMAIN` consistently, using frozen Bun lockfiles, injecting SRI into shipped HTML, stripping client-controlled IP headers in Caddy, and pinning rqlite to a specific tag plus expected commit. However, several practices should be tightened before a real production deployment or before relying on `prod-update.sh` for unattended upgrades.

The highest-priority deployment issue is that Arkfile itself appears to bind on all interfaces for ports `8080` and `8443`. `prod-deploy.sh` writes `PORT=8080`, `TLS_ENABLED=true`, and `TLS_PORT=8443`, while `main.go` starts Echo with `e.Start(":" + port)` and `e.StartTLS(":" + tlsPort, ...)`. Caddy proxies to `localhost:8443`, but the Arkfile process may still be directly reachable on public interfaces if the firewall is missing, disabled, misconfigured, or later changed. This should be fixed by making the application honor a configured bind host and setting production deploys to bind Arkfile only to `127.0.0.1`, or by otherwise forcing loopback-only binding for the app behind Caddy. This is a must-fix before production.

The firewall path currently fails open. `prod-deploy.sh` configures `firewalld` or `ufw` when available, but if neither supported firewall tool is found it only prints a warning and continues. For a production deployment script, especially while the Arkfile app can bind public interfaces, this should fail closed unless the operator explicitly passes an override such as `--external-firewall-confirmed`. A startup or post-start listening-socket check would also be valuable, so the script can detect if Arkfile, rqlite, SeaweedFS, or other internal services are externally reachable.

Secret handling should be tightened. `prod-deploy.sh` still documents `--desec-token <token>` in a way that encourages passing the deSEC API token on the command line, even though the script correctly warns that CLI args are visible in process listings and supports interactive prompting. Production-standard behavior would be to prefer interactive input or a `--desec-token-file` with strict mode checks, and to deprecate or remove command-line token input. The rqlite readiness check also uses `curl -u "arkfile-db:${RQLITE_PASSWORD}"`, which exposes the rqlite password in the process command line while curl runs. The bootstrap instructions print a command using `bootstrap --token $(sudo cat /opt/arkfile/etc/keys/bootstrap-token.bin)`, which would expose the bootstrap token in shell history and argv if copied verbatim. The cleaner fix is stdin/file-based secret handling, including an `arkfile-admin bootstrap --token-stdin` path.

Secret files are created with shell redirection before restrictive permissions are applied. `secrets.env`, `rqlite-auth.json`, `seaweedfs-s3.json`, and `/var/lib/caddy/caddy-env` are written and then `chmod`ed. With a default umask such as `022`, there can be a brief mode `0644` window. Production scripts should set `umask 077` near the top before any secret material is written, then explicitly relax specific files to `0640` only after ownership is correct.

`prod-update.sh` has insufficient rollback behavior. It backs up binaries, but if the new Arkfile or Caddy health checks fail after deployment, it exits without automatically restoring the previous binaries, static assets, service files, Caddyfile, or database schema files. It also says data/config/keys are preserved, but starting a new binary can still run application-level schema migrations, so updates can mutate database state indirectly. A production update flow should take a pre-update rqlite snapshot/export or otherwise require an explicit backup confirmation, back up static assets and service/proxy files alongside binaries, and install a rollback trap that restores the prior version if readiness checks fail.

The Caddy build path is not reproducible enough for production. `prod-deploy.sh` installs `xcaddy` with `@latest` and builds Caddy with `github.com/caddy-dns/desec` without an explicit version. This means two production deployments at different times may build different proxy code. Pin `xcaddy`, the Caddy base version, and the deSEC DNS plugin version, and record those versions in a deployment manifest.

SeaweedFS acquisition still relies on MD5 verification in `scripts/setup/05-setup-seaweedfs.sh`. That is not appropriate as the primary integrity check for production dependency acquisition. Replace it with a repo-pinned SHA-256 digest, ideally stored with the other dependency hash material, and fail closed if the downloaded artifact does not match.

The production build path may mutate dependencies during deployment. `scripts/setup/build.sh` can run `go mod tidy` and `go mod vendor` if dependency resolution or vendor checks fail. That is useful during development but non-standard for production deploy/update because it can alter `go.mod`, `go.sum`, or `vendor/` on the VPS and mask unreviewed dependency drift. Production build mode should fail if module/vendor state is inconsistent, use the checked-in vendor/lock state, and refuse to run tidy/vendor mutation.

The rqlite build path is better than most because it pins a version and expected commit, but it still has operational rough edges. `scripts/setup/06-setup-rqlite-build.sh` temporarily changes ownership of parts of `/opt/arkfile/var` and `/opt/arkfile/var/cache` to `$SUDO_USER` for build-cache access, then partially restores ownership. This is fragile in a runtime tree. Prefer a dedicated build cache outside the runtime directory, such as `/var/cache/arkfile`, with explicit build-user ownership. Also review the `GOTOOLCHAIN` handling; for “do not download toolchains during production build,” `GOTOOLCHAIN=local` is usually clearer than setting it to a detected version string.

The Caddy backend transport currently uses `tls_insecure_skip_verify` while proxying to Arkfile on localhost. Because this is loopback it is not the highest-risk issue, but it is still non-standard. Once Arkfile is loopback-bound, either proxy plain HTTP internally or configure Caddy to trust Arkfile’s generated internal CA/certificate instead of skipping verification.

`prod-update.sh` treats Caddy validation failures as warnings in some cases and skips validation when it cannot read the deSEC token. A production update should fail closed before restart if the generated Caddyfile does not validate. Missing token state should also be an error unless the script can prove the current Caddyfile does not need that token.

Static asset deployment in `prod-update.sh` overlays new files with `cp -r` but does not remove files that no longer exist in the build. This can leave stale JavaScript, source maps, or obsolete assets reachable after update. Use `rsync --delete` if available, or explicitly clear managed static directories before copying the new build output.

Service file deployment during update swallows copy failures with `2>/dev/null || true`. Expected systemd service files should be installed with hard failure semantics. Optional service files can be conditional, but broad silent failure is not production-standard because an update may appear successful while leaving old service hardening or execution settings in place.

The ownership model under `/opt/arkfile` is broad. The deploy path often `chown -R`s the full tree to `arkfile:arkfile` and even treats root-owned files as a deployment failure. Runtime systemd hardening mitigates this somewhat, but a more standard least-privilege model would keep binaries, service templates, static assets, and immutable schema/config material root-owned and grant the `arkfile` user ownership only over runtime-write paths and specific secret/key paths it must read or write.

There are also a few lower-stakes cleanup issues: `prod-deploy.sh` still tells users “use a future prod-update.sh” despite `prod-update.sh` now existing; the Caddy systemd unit grants write access to `/etc/caddy` even though Caddy should only need to read its config; and production update/deploy output should avoid recommending commands that place secrets directly in shell command lines.

The recommended first remediation batch is: bind Arkfile to loopback in production, fail closed when firewall posture is unknown, set `umask 077` before writing secrets, remove argv-based secret handling for deSEC/rqlite/bootstrap paths, and make `prod-update.sh` fail/rollback safely. The second batch is to pin Caddy/xcaddy/deSEC module versions, replace SeaweedFS MD5 with SHA-256, add a production build mode that refuses dependency mutation, remove Caddy backend `tls_insecure_skip_verify` or replace it with trusted internal CA validation, and revisit the broad `/opt/arkfile` ownership model.

---
