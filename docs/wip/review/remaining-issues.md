# Arkfile Open Security Issues

This document is a code-verified inventory of priority security issues that are still open in Arkfile as of 2026-06-03. Every entry below was confirmed by reading the live source tree at the time. It is intended as the working baseline for planning future remediation sessions.

Issues here are grouped by app-functionality and by privacy/security concept. Each issue lists a plain-language title, the concrete file location where it lives, what it is, why it matters, and a rough effort note.

---

## 1. Server-Side Metadata and Privacy Leakage

Arkfile's central promise (per `docs/AGENTS.md`) is that the server, and especially any third-party S3 storage backend, learns nothing about the nature of a user's data. These items are places where that promise is not fully kept today.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| File size leaks to the server before padding | `handlers/uploads.go` (server applies random padding to the last chunk) | Padding is applied server-side, so the server observes the true unpadded ciphertext size before padding. A client-side padding strategy would prevent the server from ever seeing the unpadded size. | Medium |
| Account key reused as the metadata encryption key | `crypto/file_operations.go` / metadata encrypt-decrypt paths | The same Account-KEK that wraps per-file FEKs also directly encrypts filename and SHA-256 metadata. There is no key domain separation (e.g. an HKDF-derived metadata subkey). A dedicated subkey would isolate the metadata-encryption role from the FEK-wrapping role. | Low-Medium |

---

## 2. File Transfer Integrity and Robustness

File content confidentiality is solid, and per-chunk tamper detection is now enforced at the AEAD layer (the chunk/FEK/metadata AAD binding has landed). The items below are the remaining integrity-adjacent and robustness gaps in the upload/download pipeline. Most are now lower-risk because the AEAD layer catches active tampering, but they remain real correctness or availability bugs, especially for the large-file-on-constrained-device use case that `docs/AGENTS.md` emphasizes.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| Client-supplied chunk hash is never verified | `handlers/uploads.go` (`X-Chunk-Hash` header) | The header's format is validated (64 hex chars) and the server computes its own streaming hash, but the client's claimed per-chunk hash is never compared against the server-computed value. The header therefore provides no integrity guarantee; it should either be verified or removed. | Low |
| Multi-provider download fallback skips stored-blob verification | `handlers/downloads.go` (provider fallback path) | When a download falls back to a secondary provider, the served blob is not checked against the recorded `stored_blob_sha256sum`. A divergent or corrupted secondary copy would be served without detection. | Medium |
| In-process upload hash state lost on restart | `handlers/uploads.go` (`streamingHashStates` / `storedBlobHashStates` in-memory maps) | The per-session SHA-256 hasher state lives only in process memory. A server restart mid-upload corrupts the in-flight upload's integrity record, forcing the client to restart the whole upload. | Medium |
| Streaming download writes plaintext to disk before hash verification | `client/static/js/src/crypto/streaming-download.ts` | The browser streams decrypted bytes to disk and only verifies the end-of-file plaintext SHA-256 afterward. With per-chunk AAD now in place this is much less dangerous, but the end-of-file hash result still arrives after the file is already on disk. | Medium |
| Blob-fallback download path performs no end-of-file hash check | `client/static/js/src/crypto/streaming-download.ts` (Blob fallback when Service Worker is unavailable) | The fallback path skips the end-of-file SHA-256 verification entirely. AEAD still protects each chunk, but the whole-file content check is absent on this path. | Low-Medium |
| Background replication is uncancellable | `handlers/uploads.go` (`replicateToSecondary` uses a fire-and-forget goroutine with `context.Background()`) | Secondary-provider replication runs in a detached goroutine with a non-cancellable context. It cannot be cancelled or cleanly shut down, and it is not tied to the request lifecycle. Routing it through the admin task runner (or passing a cancellable context) would make it observable and stoppable. | Medium |

---

## 3. OPAQUE Protocol Correctness

The OPAQUE primitives are sound and the CGO boundary was previously audited. These are the remaining correctness and hygiene items on the OPAQUE path.

| Issue | Location | What and why it matters | Effort |
|---|---|---|---|
| Server public key generated independently rather than derived | `auth/opaque.go` (`opaque_server_public_key` obtained via `GetOrGenerateKey`) | The OPAQUE server public key is stored as its own independently generated key instead of being derived from the server private key. Deriving it would remove a class of "the stored public key does not match the private key" failure modes. | Low-Medium |
| Server identity hardcoded as "server" | `auth/opaque_multi_step.go`, `auth/opaque_client.go` (`idS := []byte("server")`, with a "could be configurable later" comment) | The OPAQUE server identity is a fixed literal rather than being bound to the deployment FQDN. Binding it to the deployment identity strengthens the protocol's domain separation between deployments. Note the greenfield "for now" comment here is exactly the kind of placeholder `docs/AGENTS.md` asks us to flag. | Low-Medium |
| CGO password-buffer hygiene | `auth/opaque_wrapper.c`, `auth/opaque_multi_step.go` (`StoreUserRecord` double-buffer pattern) | The password buffer is not zeroed in the C heap after use, and the double-buffer pattern in the record-store path is internally inconsistent. Tightening this reduces the window in which password material lingers in process memory. | Medium |

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
| Origin-header trust in share URL construction | `handlers/file_shares.go` (share URL built from the request Origin) | The share URL is constructed from the client-supplied Origin header when no base URL is configured. A crafted Origin can produce a misleading share URL (owner-side phishing / self-XSS amplification). Pinning to a configured base URL closes this. | Low |
| Daily-rotating EntityID resets the rate-limit budget | `logging/entity_id.go` (day-bucketed HMAC) | The anonymous EntityID rotates daily, so an attacker's per-EntityID rate-limit budget resets each day and can be multiplied by waiting out the rotation window. The rotation period is a privacy-vs-abuse tradeoff worth revisiting. | Medium |
| Share access-attempts table grows unbounded | `database/unified_schema.sql` (`share_access_attempts`) and its writers | The rate-limit / access-attempt table has no DB-side cleanup or retention policy, so it grows without bound over time. A periodic prune job would bound it. | Low |

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
| Residual "for now" / placeholder comments | OPAQUE server identity (see section 3) and similar | Any comment indicating a temporary or placeholder implementation should be flagged and resolved, per `docs/AGENTS.md`. | Low |

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

If a future check finds any of the above regressed, treat that as a high-priority regression rather than a planned item.

---

## Where to Focus First (Prioritization)

The single highest-leverage, lowest-effort item is removing the plaintext owner username from S3 object metadata. It is the clearest remaining violation of Arkfile's core promise that the storage layer learns nothing about user data, it leaks identity to potentially third-party storage providers rather than only to the operator, and the fix is small because the database already holds the file-to-owner mapping. Pairing that with a dedicated HKDF-derived metadata key (so the Account key is no longer doing double duty as the metadata-encryption key) makes the privacy-leakage bucket a clean, self-contained first pass with strong alignment to the project's stated values.

The second area to tackle is host and infrastructure hardening, because the wins are cheap and they close real, currently-open exposure. Binding rqlite to loopback removes a database and Raft surface that today is protected only by application-level auth and a correctly configured firewall, and adding core-dump suppression at the systemd level (and, ideally, inside the application launch path so the protection survives on non-systemd hosts) directly protects the user-secret master key that was just hardened in memory. While doing this work, keep the cross-platform notes above in view so we do not bake in assumptions that make a future FreeBSD, OpenBSD, or Alpine deployment harder than it needs to be.

The third area is file-transfer robustness. With per-chunk AAD now enforced, the active-tampering risk these items once carried is largely mitigated, so they drop below the privacy and infrastructure work in urgency. They are still worth doing, however, because several are plain correctness and availability bugs that bite exactly the use case the project cares most about: a user on a constrained device moving a very large file. Persisting upload hash state across restarts and verifying the served blob on the multi-provider fallback path are the two most valuable items in this group; resolving (or removing) the unverified client chunk hash is a quick cleanup that removes a misleading no-op.

Everything else, including the OPAQUE correctness items, the username normalization policy, the sharing residuals, and the code-hygiene cleanups, is genuinely useful but lower-leverage, and can be slotted into later sessions once the three areas above are in good shape. The OPAQUE server-identity and public-key-derivation items in particular are good candidates to bundle together into a single focused OPAQUE-hardening session rather than being done piecemeal.
