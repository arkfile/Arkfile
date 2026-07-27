# Security Cleanup and Integrity-Test Preparation

## Goal

Improve Arkfile's current security posture and the accuracy of its security claims without beginning a months-long refactor. Add focused tests and shared cryptographic vectors while the implementation is being tightened. Defer creation of `offline-integrity-test.sh` and `online-integrity-test.sh` until these changes stabilize, so the scripts orchestrate established checks rather than encoding moving assumptions.

This is a greenfield cleanup. Format and schema changes are allowed when they produce a cleaner canonical architecture. Do not preserve obsolete derivation or envelope paths as compatibility fallbacks. Preserve Arkfile's intended capabilities: browser and CLI interoperability, offline `.arkbackup` decryption, account-key caching, custom-password files, anonymous sharing, and both browser download paths.

## Test-size approval boundary

No unit, integration, browser, E2E, fuzz-seed, benchmark, or future integrity test may create, declare, download, upload, decrypt, or otherwise use a test file or logical test payload larger than 100 MB (100,000,000 bytes) without the developer's explicit approval for that specific addition. This restriction includes sparse files, generated streams, mocked size declarations, fixtures, temporary files, and test-script defaults.

Streaming behavior should be tested with small boundary inputs and a representative sequence such as 1 MiB, 20 MiB, 50 MB, and 100 MB. Tests can prove chunk-by-chunk processing, bounded queues, cleanup, and absence of full-file accumulation without using multi-gigabyte fixtures. The 6 GB constrained-device scenario remains an architectural requirement and manual acceptance scenario, not an automated test-file size.

## Required security contract

Arkfile protects passwords, file plaintext, owner metadata, FEKs, and share-envelope plaintext from a passive server, stolen server data, storage providers, and an unmodified server interacting with an authentic client. OPAQUE authentication and file encryption remain independent domains.

A web application cannot protect secrets from an attacker who controls the origin and replaces its JavaScript or WASM. Such an attacker can capture future passwords, keys, metadata, and plaintext during browser operations. AES-GCM protects an authentic client from accepting modified ciphertext; it cannot protect a client implementation replaced by the attacker. The independently installed CLI has a separate software-distribution trust boundary. Documentation and tests must preserve this distinction and must not claim protection from malicious client replacement.

The server intentionally knows the operational metadata listed in `docs/security.md`, including ownership, pre-padding encrypted size, padded size, chunk count, plaintext chunk size, encrypted-stream and stored-object digests, password routing type, and FEK-envelope key type. Privacy checks must allow these fields while rejecting protected plaintext.

## Immediate codebase priorities

### Tighten secret handling and logging

Review security events, application logs, handler errors, debug output, and administrative activity records for paths that can persist request bodies, passwords, keys, plaintext filenames, plaintext digests, password hints, file fragments, or raw IP addresses. Sensitive-value filtering based only on field names is insufficient because a secret can be placed under a generic key such as `message`, `reason`, or `details`.

Prefer narrowly scoped or typed security-event construction over arbitrary maps. Add focused tests proving that approved event helpers reject or redact protected values. Add a small number of custom static checks only where the forbidden pattern is unambiguous, such as raw `RealIP` or `RemoteAddr` values entering logs, file-crypto key derivation being imported into server handlers, or direct construction of security events outside approved helpers. Do not attempt a broad whole-program secret-taint analyzer in this cleanup.

Verify that production and production-like build paths cannot enable development-only secret output, OPAQUE WASM tracing, or unsafe authentication debugging. Development tracing may remain available through the explicit development workflow, but production deployment checks should fail if it is enabled.

### Preserve and verify both browser download paths

Retain the Service Worker streaming path as the preferred path for large downloads and retain the Blob fallback for browsers or systems where Service Worker streaming is unavailable. Do not remove the fallback and do not impose a blanket Arkfile file-size cap on it.

The Blob fallback necessarily retains the complete decrypted plaintext in browser-managed Blob storage before triggering the download. Preserve the existing prominent warning for large fallback downloads and make the limitation explicit in security and user documentation. Continue authenticating every encrypted chunk, compute the whole-file plaintext digest before triggering the Blob download, revoke the Blob URL on mismatch or failure, and avoid claiming success until verification passes.

Add tests that force both routing outcomes. The Service Worker tests should prove bounded chunk flow and correct interruption messaging. The Blob tests should prove that fallback remains reachable, warning behavior is triggered for large files, a hash mismatch blocks the download trigger and revokes the URL, and successful verification permits the download. Resource tests must not claim that Blob memory is independent of file size.

### Establish a cross-client cryptographic contract

Create a committed, versioned fixture corpus consumed by both Go and TypeScript. Expected values must not be regenerated during routine tests. Use independently derived or manually pinned expected bytes so one client is not treated as the oracle for the other.

The first shared vectors should cover chunk AAD, FEK-envelope AAD, metadata-field AAD, account and custom key derivation from explicit salts, FEK key-type and salt-bearing header bytes, one or more fixed-nonce AES-256-GCM primitive cases, empty and boundary-size inputs, and deliberate corruption or truncation. Add test-only fixed-nonce support without exposing caller-selected nonces through normal production encryption APIs.

Share envelopes should initially use cross-client decrypt compatibility vectors. Byte-identical encryption vectors should wait until canonical plaintext serialization and field ordering are specified. Server padding should use Go-only deterministic tests because it is not a TypeScript client format. `.arkbackup` fixtures should remain Go-only unless a TypeScript implementation is introduced.

Add short seeded fuzz tests for parsers that consume untrusted bytes, beginning with FEK-envelope headers, share envelopes, share tickets, and `.arkbackup` bundles. Keep the committed malformed-input corpus deterministic; longer coverage-guided fuzz campaigns remain optional.

### Exercise state and concurrency invariants

Add focused tests for upload initialization, chunk acceptance, completion, quota accounting, deletion, share creation, ticket issuance, expiry, revocation, and download limits. Include concurrent completion, ticket use, and revocation cases where duplicate accounting or stale authorization could occur.

Use a small executable reference model if it reduces duplicated test setup, but do not begin TLA+, Tamarin, ProVerif, Gobra, or generated verified implementations as part of this cleanup. The executable tests can later supply traces and clarified invariants to formal models.

### Replace deterministic file-key salts without losing portability

Replace username-derived Account Key and Custom Key salts with cryptographically random 32-byte public salts. This does not prevent per-record offline password guessing, but it removes deterministic salt reuse for the same username across deployments and prevents one custom password from deriving the same Custom Key for every file owned by a user.

Generate one Account Key salt client-side during account registration. Store it as public account cryptographic metadata and return it to an authenticated client before Account Key derivation. Preserve this salt during OPAQUE re-registration and ordinary authentication changes. The Account Key remains `Argon2id(account_password, account_kdf_salt)` and remains independent of OPAQUE outputs. Account-key cache records must bind to the username, salt, KDF profile/version, and derived key so stale cached keys cannot cross a salt or parameter change.

Generate a new Custom Key salt client-side for each custom-password file. Carry it in the owner FEK envelope so the client can parse the public salt before deriving the Custom Key. The same custom password used for two files must produce different Custom Keys.

Define one new canonical owner FEK-envelope version rather than retaining parallel legacy parsing paths. Its authenticated header should identify the envelope version, key type, KDF profile/version, and 32-byte salt, followed by the AES-GCM nonce and wrapped FEK. Bind the complete header and file ID into AAD. For account-wrapped files, the envelope salt must equal the account's stored Account Key salt. For custom-wrapped files, it is the per-file random salt.

Add `account_kdf_salt` and an explicit KDF profile/version to `.arkbackup` metadata. Offline decryption must derive the Account Key from the password and salt embedded in the bundle, with no server dependency. Preserve `owner_username` for metadata AAD, but stop requiring the caller to supply a username when a self-describing bundle already contains it. If the caller supplies a username, require an exact normalized match with the bundle. Custom-file backups obtain their Custom Key salt from the embedded FEK envelope.

Treat all salts as public values. A captured authenticated FEK envelope still permits offline guesses because successful AES-GCM authentication identifies a correct derived key. Security against those guesses depends on password strength and Argon2id cost, not salt secrecy or the fact that the derived key wraps a random FEK.

Remove username-derived salt helpers, constants, comments, and tests once the new path is complete. Do not retain deterministic derivation as a fallback. Because Arkfile is greenfield, development data may be reset through the normal developer workflow rather than adding production migration code.

The expected implementation surface is:

- `database/unified_schema.sql` and `models/user.go`: persist the public Account Key salt and KDF profile/version as required account fields.
- `handlers/auth.go`, registration/reregistration handlers, and their response types: accept the client-generated salt at registration, preserve it during OPAQUE record rotation, and return it after successful authentication through a single canonical account-crypto metadata response.
- `client/static/js/src/auth/register.ts` and `login.ts`: generate the Account Key salt at registration and obtain the stored value after login before deriving or unlocking the Account Key.
- `client/static/js/src/crypto/file-encryption.ts`, `constants.ts`, and `account-key-cache.ts`: replace username-derived salt construction with explicit validated salt inputs and bind cached keys to the KDF metadata.
- `crypto/key_derivation.go` and `crypto/file_operations.go`: accept explicit salts, define the canonical owner-envelope parser/writer, and remove deterministic salt helpers.
- `client/static/js/src/files/upload.ts`, `download.ts`, `share.ts`, and metadata helpers: create, carry, parse, and validate salt-bearing envelopes consistently with Go.
- `cmd/arkfile-client/commands.go`, `offline_decrypt.go`, `reregistration.go`, and shared CLI crypto helpers: consume account crypto metadata, preserve it through re-registration, and use bundle-contained salts offline.
- `handlers/export.go` and the matching CLI/browser export code: include the Account Key salt and KDF profile in self-describing `.arkbackup` metadata without exposing any secret key material.

### Normalize cryptographic APIs and formats

Go and TypeScript should expose equivalent conceptual operations even where language APIs differ: generate a salt, derive an Account or Custom Key from an explicit salt and KDF profile, create and parse an owner FEK envelope, wrap and unwrap an FEK with AAD, encrypt and decrypt metadata fields, and seal and open share envelopes.

Keep randomness at the outer operation boundary so production callers cannot accidentally reuse nonces or salts. Deterministic helpers that accept caller-provided nonces belong in test-only code or unexported primitive tests. Parsers must reject unsupported versions, unknown key types, wrong salt lengths, short nonces, truncated tags, trailing bytes where the format forbids them, and inconsistent account salts before expensive or state-changing work.

Specify canonical byte layouts and AAD fields next to the implementation and in versioned fixtures. Avoid relying on JSON object property order for cryptographic equivalence. Where JSON is encrypted, define canonical serialization or test cross-client decryption of fixed plaintext bytes rather than assuming independently serialized objects are byte-identical.

### Harden build-profile boundaries

Production browser builds must compile with debug logging disabled and without OPAQUE trace instrumentation. Production and production-like deployment scripts should verify the resulting settings and fail closed if development-only tracing is present. Development builds may retain explicit tracing, but tests and documentation must not treat development traces as representative production logging.

Do not add third-party scripts to authentication or file-operation pages. Review CSP, cache policy, service-worker scope, static-asset MIME types, and production source-map exposure as defense-in-depth controls. Document that these controls reduce accidental injection and deployment mistakes but do not protect against an operator who controls the origin and intentionally replaces the client.

## Detailed test additions

### Shared Go and TypeScript conformance fixtures

Add a single committed JSON corpus under `crypto/testdata/` containing explicit input bytes and expected output bytes. Include a corpus format version and cryptographic format versions. Go and TypeScript must both read the same file; neither test suite may rewrite it.

Add matching AAD cases to `crypto/aad_test.go` and `client/static/js/src/__tests__/aad.test.ts`. Cover chunk AAD, FEK-envelope AAD including the complete salt-bearing header, each encrypted metadata field label, normalized usernames where applicable, file-ID boundaries, chunk zero, final chunk, and malformed identifiers.

Replace deterministic-username KDF expectations in `crypto/key_derivation_test.go` and `client/static/js/src/__tests__/file-encryption.test.ts` with explicit-salt vectors. Both suites should prove equal Account and Custom Keys for the same password, salt, and profile; different salts produce different keys; account and custom contexts remain separated; malformed salt lengths fail; password limits are enforced; and no OPAQUE session material is accepted by file-key APIs.

Turn `crypto/argon2_conformance_test.go` into a fixture consumer rather than a routine fixture generator, matching `client/static/js/src/__tests__/argon2-conformance.test.ts`. If a fixture-generation utility is retained, keep it outside ordinary tests and require deliberate developer invocation.

Add matching AES-GCM primitive vectors to `crypto/gcm_test.go` and `client/static/js/src/__tests__/aes-gcm.test.ts` or `primitives.test.ts`. Cover fixed key, nonce, plaintext, and AAD bytes; empty plaintext; altered AAD; altered nonce; altered tag; truncation; and output layout. Production encryption must still generate fresh random nonces internally.

Add owner-envelope cases to `crypto/file_operations_test.go` and `client/static/js/src/__tests__/metadata-helpers.test.ts` or a dedicated `fek-envelope.test.ts`. Cover account and custom envelope creation/parsing, random salt placement, header authentication, file-ID binding, key-type binding, unknown versions, unknown key types, wrong salt length, truncation, salt substitution, and cross-client unwrap of committed vectors.

Add share-envelope cases to `crypto/share_kdf_test.go` and `client/static/js/src/__tests__/share-crypto.test.ts`. Cover fixed plaintext bytes, random-salt layout, share/file AAD binding, wrong password, wrong share ID, wrong file ID, malformed KDF parameters, truncation, and Go-encrypt/TypeScript-decrypt plus TypeScript-encrypt/Go-decrypt fixtures where deterministic test inputs are available.

### Go-only unit and parser tests

Extend `cmd/arkfile-client/offline_decrypt_test.go` with the new `.arkbackup` salt and KDF-profile fields. Prove password-only offline decryption using the bundle's owner username and Account Key salt, optional caller-username mismatch rejection, account-key-file operation, agent-key operation, custom-file salt extraction, wrong salt failure, unsupported KDF profile rejection, malformed header rejection, digest mismatch cleanup, and output removal after interrupted or failed decryption.

Extend `handlers/export_rotation_test.go` and relevant export handler tests to prove that exported metadata contains the correct public Account Key salt and KDF profile, custom salts remain in the FEK envelope, owner username and file ID remain AAD-compatible, and export streams encrypted bytes without buffering the object.

Extend `crypto/file_operations_test.go` with uniqueness tests proving separate files receive distinct custom salts and separately generated envelopes receive distinct nonces. These are invariant tests, not statistical randomness tests.

Add native Go fuzz targets beside their parsers: FEK owner envelopes in `crypto/file_operations_test.go`, share envelopes in `crypto/share_kdf_test.go`, tickets in `crypto/share_ticket_test.go`, and `.arkbackup` headers in `cmd/arkfile-client/offline_decrypt_test.go`. Seed each target with valid committed fixtures and representative truncations. Fuzz assertions should require no panic, bounded allocation, deterministic rejection classes where practical, and no accepted object that violates format invariants.

### TypeScript-only browser unit tests

Extend `client/static/js/src/__tests__/account-key-cache.test.ts` so cache entries are bound to username, Account Key salt, and KDF profile/version. Prove cache misses after any binding value changes and prove key material is cleared on lock, logout, expiry, and replacement.

Extend `client/static/js/src/__tests__/streaming-download.test.ts`, `sw-streaming-download.test.ts`, and `sw-download-handler.test.ts` to force Service Worker success, unavailable, initialization failure, first-fetch race, cancellation, retry, and Blob fallback routing. Assert bounded queued chunks for the Service Worker path using small synthetic chunks rather than large files.

Add or extend download-integrity tests to prove that Blob fallback remains available without an Arkfile size cap, large-download warnings appear at the configured warning threshold, plaintext digest mismatch prevents trigger and revokes the Blob URL, successful verification triggers once, URLs are revoked after use, and interruption messaging does not promise deletion of operating-system partial files.

Extend `client/static/js/src/__tests__/export.test.ts` to cover self-contained backup metadata, Account Key salt and KDF profile propagation, owner username handling, custom envelope preservation, export-token expiry/error handling, and streaming export initiation without assembling the encrypted backup in page memory.

### Server unit and integration tests

Extend `logging/security_events_test.go` with protected canaries under both sensitive and generic field names. Cover account passwords, custom passwords, share passwords, plaintext filenames, password hints, plaintext digests, file fragments, FEKs, Account Keys, OPAQUE outputs, tokens, and raw IP addresses. Approved structured fields such as EntityID, file ID, username, encrypted sizes, and routing types must remain usable.

Extend `logging/entity_id_test.go` and `handlers/middleware_test.go` to prove raw peer addresses and forwarded addresses are normalized only for EntityID derivation and never persisted or emitted. Include malformed forwarding headers, IPv4, IPv6, and proxy-boundary cases.

Extend `handlers/uploads_test.go` and `handlers/files_test.go` with transition tests for upload initialization, exact chunk boundaries, duplicate chunks, missing chunks, completion replay, interrupted upload cleanup, completion visibility, deletion, and quota accounting. Include concurrent completion attempts and assert exactly one terminal transition and one accounting effect.

Extend `handlers/file_shares_test.go` and `handlers/share_ticket_test.go` with deterministic clock-controlled tests for creation, ticket issuance, expiry, revocation, download limits, duplicate ticket use, concurrent final allowed downloads, and revocation racing ticket issuance. Assert that no new authorization is issued after revocation or expiry and limits cannot be consumed below zero or bypassed by retries.

Extend billing and storage tests where state transitions affect credits, projected storage, padded size, replication, or deletion. Keep policy calculations deterministic and avoid real external object-storage services in unit/integration tests.

### Build, deployment, and later E2E checks

Add focused checks to the existing build/deployment test structure rather than creating the integrity scripts early. Verify production TypeScript compilation sets `ARKFILE_DEBUG_LOG=false`, production WASM is built without trace flags, development-only APIs are disabled outside development, source-map behavior matches policy, and deployed static assets use expected service-worker scope and content types.

After native unit and integration tests pass, add compact E2E cases for cross-client upload/download, account and custom salt handling, `.arkbackup` export/offline decrypt, both browser download routes, share revocation/limits, privacy canaries, and CLI interruption. Every automated payload remains at or below 100 MB unless the developer explicitly approves a larger case.

Do not duplicate exhaustive vector cases in E2E. Unit tests own byte-level format behavior; integration tests own state and persistence boundaries; E2E owns wiring between real built clients and the deployed server; future integrity scripts own orchestration and cross-surface privacy/resource assertions.

## Implementation shape and order

1. Finalize and document the random-salt and owner-envelope formats, KDF profile/version representation, AAD composition, and `.arkbackup` fields.
2. Add the shared fixture corpus and paired Go/TypeScript fixture readers before changing production derivation, so the new contract is executable.
3. Implement explicit-salt Account and Custom Key APIs in Go and TypeScript, then implement the canonical salt-bearing owner envelope.
4. Add account salt generation, persistence, authenticated retrieval, cache binding, registration behavior, and OPAQUE re-registration preservation.
5. Update browser and CLI upload/download, metadata, sharing, and `.arkbackup` paths to use the canonical formats. Remove deterministic salt code and obsolete envelope parsing once callers are converted.
6. Tighten structured logging and production build-profile enforcement.
7. Complete paired crypto tests, browser route/integrity tests, server state/concurrency tests, parser fuzz targets, and documentation audits.
8. Run the normal developer rebuild/deployment and E2E workflow appropriate to the environment. Only after behavior stabilizes should the two integrity orchestration scripts be created.

## Documentation work

Keep `docs/security.md` aligned with the implementation and threat model. It must describe the trusted-client boundary, distinguish passive server compromise from active browser-client replacement, preserve the intentional operational-metadata classification, describe OPAQUE and Argon2id as independent systems, accurately describe FEK and share-envelope wrapping, and avoid absolute claims that password policy or Argon2id make guessing impossible.

Document the two browser download paths without presenting the Blob fallback as a defect to remove. The Service Worker route provides bounded-memory streaming. The fallback provides broader browser compatibility by assembling plaintext in a Blob, with an explicit memory/storage warning and verification before download trigger.

Review the remainder of `docs/security.md` for aspirational commands, metrics, log locations, automated responses, or security properties that are not implemented. Either verify them against the code and deployment scripts or clearly label them as operational recommendations rather than current Arkfile behavior.

## Deferred integrity scripts

Do not create the scripts until the cleanup checks and fixtures above are stable.

`scripts/testing/offline-integrity-test.sh` will eventually orchestrate shared Go/TypeScript conformance vectors, malformed-input tests, short parser fuzzing, focused state-model tests, custom Arkfile analyzers, and selected generic static or dependency checks. It must not require a running server, `dev-reset.sh`, or completed E2E state.

`scripts/testing/online-integrity-test.sh` will eventually require a live development deployment and use dedicated integrity users, files, and shares. It should create its own fixtures through the development approval API rather than mutate E2E or Playwright users. It will exercise privacy canaries, inspect post-test log/database/storage/temp-file deltas, measure CLI streaming memory across increasing file sizes no larger than 100 MB without explicit developer approval, verify CLI interruption cleanup, and execute selected live authorization and accounting races.

The online script must treat Service Worker streaming and Blob fallback as different resource models. It may assert bounded memory for CLI and Service Worker paths, but it must not assert bounded memory for Blob assembly or universally claim that an operating-system download manager leaves no partial file after interruption.

## Completion criteria before script creation

The security guide contains no known contradiction between OPAQUE authentication and Argon2id file-key derivation, no absolute protection claim against malicious browser-client replacement, and no claim that random public salts prevent per-record offline guessing.

Both browser download routes remain functional and have explicit routing, integrity, warning, failure, and success tests. Account and per-file custom salts are random, public, format-bound, and sufficient for self-contained offline backup decryption. Deterministic username-derived salt paths have been removed. The shared Go/TypeScript fixture corpus is committed and consumed without routine regeneration. Initial parser fuzz targets and state/concurrency tests pass through their native test runners. Production build and deployment checks exclude development tracing and unsafe secret output. Logging tests cover the protected plaintext classes that the future online canaries will search for. No automated test exceeds the 100 MB approval boundary.
