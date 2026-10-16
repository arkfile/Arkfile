# Client-Side Zstd Compression

## Status and dependencies

This is a proposed implementation plan. No compression work starts until `docs/wip/admin-sec.md` and then `docs/wip/auto-logout.md` are implemented, migrated on a populated test deployment, and passing their unit, end-to-end, and Playwright coverage. That order is required because compression changes upload-session state, transfer routes, finalization, cancellation, expiry, and long-running transfer behavior. The session-family middleware and its one-file grace rules must already be the authority before new upload states or routes are added.

## Reasoning and high-level vision

Arkfile can reduce object-storage use, transfer bytes, and user storage charges by compressing suitable files on the client before client-side encryption. The server must never receive plaintext or perform content compression, and compression must not weaken the existing random per-file FEK, per-chunk AES-256-GCM authentication, encrypted owner metadata, anonymous-share model, or bounded-memory support for a multi-gigabyte file on a constrained device. The intended pipeline is plaintext SHA-256 and client-side deduplication first, followed for a non-duplicate compressible file by a streaming zstd encoder whose output is accumulated into fixed 16 MiB encryption transport chunks. Each full transport chunk is encrypted and uploaded as one S3 multipart part; only the final chunk is shorter. Compression input boundaries and encryption/upload boundaries are deliberately independent.

This design does not compress each existing 16 MiB plaintext chunk into a variable-length encrypted object part. Variable parts would break the simple fixed-range download layout, reveal the local compressibility of every plaintext region, require a permanent offset index, and can violate S3's minimum size for non-final multipart parts. Instead, one continuous zstd byte stream is divided after compression into the same fixed-size AEAD transport chunks Arkfile already knows how to range-read. The compressor is not flushed at transport boundaries. At end of file it is finalized, its remaining output is drained, and the final complete or partial transport chunk is encrypted and uploaded.

Compression is an additive payload format for new uploads. Existing files remain untouched and readable. Files that are too small or are unlikely to save a configured minimum percentage continue through the current uncompressed payload format. Storage-object deduplication, shared objects, FEK reuse, content-addressed storage, and migration or recompression of existing objects are separate projects and are explicitly outside this work.

## Required prototype and measurement gate

Before schema or production protocol work, build a disposable local prototype of streaming zstd compression and decompression in the browser and Go CLI. The prototype must use the candidate production libraries and build path, not an unrelated desktop-only benchmark. Measure zstd levels 1 and 3 on representative text, logs, source trees, database dumps, office formats, PDFs, JPEG, audio, video, archives, random data, and mixed-content files. Measure compression ratio, compression and decompression throughput, browser main-thread responsiveness, worker overhead, peak resident memory, WASM download size, startup time, and battery-sensitive CPU time on a constrained mobile-class device as well as a desktop.

The prototype must prove that a 6 GB input can be processed with memory bounded independently of file size, that backpressure keeps at most a small fixed number of buffers alive, and that Go and browser implementations can decode each other's standard zstd frames. Byte-identical compressed output is not required. The format requires interoperable standard frames, fixed profile limits, and identical decompressed plaintext.

If no browser implementation meets the memory, responsiveness, build-reproducibility, and supply-chain requirements, stop the feature rather than landing a CLI-only format or an unfinished browser path. Browser and `arkfile-client` support ship together. The selected zstd source and version must be pinned and built locally; no runtime CDN, remote worker, or server compression service is permitted.

## Shared compression profile

Add one embedded `crypto/compression-params.json` as the source of truth for payload format version, algorithm identifier, zstd level, frame checksum policy, maximum decoder window, transport plaintext chunk size, sampling limits, minimum source size, and minimum projected saving required to choose compression. Go code embeds and validates this file. The server exposes the exact embedded bytes at a public config endpoint for the browser, while the CLI uses the embedded values directly. As with the existing cryptographic configuration, clients also carry compile-time safety floors and reject a server profile that exceeds the supported decoder window or otherwise weakens required limits.

The initial compressed payload format uses one continuous zstd frame with a pledged original content size and no dictionary. The encoder remains open across every 16 MiB encryption boundary and is finalized only at end of file. No filename, password, tag, hint, account metadata, or bytes from another file enter the compression context. A later seekable or independently framed format would receive a different payload format version rather than silently changing version 2.

The exact compression level, minimum file size, sample size, sample placement, and required saving remain measurement decisions, but they become locked values in the shared profile before implementation proceeds. The default should favor fast compression and low battery use over maximizing ratio.

## Upload decision and bounded sampling

The existing plaintext SHA-256 pass remains first and continues to feed the client-only digest cache. While reading the file for that hash, the client may retain a deterministic, bounded set of sample windows distributed across the beginning, interior, and end of the file. The retained sample budget is fixed by the shared profile and does not grow with file size. No zstd work is required until the digest cache confirms that the file is not a duplicate.

For a non-duplicate, the client compresses the retained samples with the selected profile and estimates whether the complete file is likely to clear the configured saving threshold. This estimate only chooses compressed or legacy format. It is never treated as the authoritative final compressed size. Sampling only the first chunk is insufficient because files can contain materially different regions.

If the sample does not clear the threshold, upload uses the existing payload format and exact existing size calculation. If it clears the threshold, the client obtains the zstd library's guaranteed maximum output bound for the complete source under the exact chosen framing. The maximum pre-padding encrypted reservation is the compression bound plus AES-GCM overhead for the maximum possible number of 16 MiB transport chunks. Integer arithmetic must be checked for overflow before any request is made.

The guaranteed bound is a quota safety limit, not the stored size and not a promise that meaningful compression will occur. A file may compress less well than its sample predicted but cannot exceed its accepted reservation. If a library cannot provide a documented bound for the exact streaming mode, Arkfile uses a conservative bound proved from the pinned library or does not use that mode.

## Payload formats and authenticated metadata

Payload format 1 remains the existing format: original plaintext is divided directly into fixed chunks, each chunk is encrypted under the current `BuildChunkAAD(file_id, chunk_index, total_chunks)`, and existing metadata and bundle rules remain valid.

Payload format 2 is the compressed format: zstd output bytes, not original plaintext bytes, fill the fixed 16 MiB AEAD transport chunks. A new domain-separated AAD constructor binds a fixed payload-format label, file ID, payload format version, and chunk index. It intentionally does not bind a total chunk count that is unknown when early chunks are encrypted. The format-1 AAD function and vectors remain unchanged forever.

Truncation protection for format 2 comes from a small FEK-encrypted payload manifest created after zstd reaches end of file. The manifest contains its own version, payload format, compression profile identifier, original plaintext size, compressed-stream size before AEAD overhead, final pre-padding encrypted size, transport chunk size, total chunk count, and original plaintext SHA-256. Its AES-GCM AAD binds the file ID, a permanent manifest field label, and the payload format version. A downloader unwraps the FEK and authenticates this manifest before requesting content chunks. It rejects any mismatch between the authenticated manifest and server-visible transport metadata before yielding plaintext.

Owner-only display metadata is stored separately as one Account-Key-encrypted payload metadata object, with AAD bound to file ID, owner username, and a permanent `encrypted_payload_metadata` label. It contains the logical original size and payload format information needed by the owner's list, share creation, and client UI. New clients create this field for both compressed and uncompressed uploads. For older format-1 records where it is absent, new clients derive the exact original size from the existing encrypted-stream length and chunk count.

The FEK owner envelope remains version 2. Compression describes the file payload, not how the FEK is wrapped, so the compression feature must not overload or bump the owner-envelope format.

## Streaming compression and transport chunking

After format 2 is selected and the upload session is initialized, the client opens one zstd encoder and reads the source incrementally. Encoder output feeds a bounded accumulator. Whenever the accumulator contains 16 MiB, that complete transport plaintext is eligible for AES-GCM encryption. The client retains one complete transport chunk until it has observed at least one later compressed byte or zstd end-of-frame. This one-chunk lookbehind guarantees that the client can identify the final multipart part even when compressed output is an exact multiple of 16 MiB.

Once more output proves a retained chunk is not final, encrypt it with format-2 chunk AAD, calculate the encrypted-chunk SHA-256 used by the upload transport, upload it, and release its buffers before proceeding. At EOF, call the zstd finalization operation, drain every footer and buffered output byte, then encrypt the retained final full or partial chunk. No zstd flush is performed merely because an encryption boundary was reached.

Backpressure permits only the current source buffer, zstd workspace, one retained transport chunk, the accumulator for the following bytes, and one encrypted upload body to be live. Browser implementations must transfer ArrayBuffers to and from a dedicated same-origin worker rather than clone them, and the producer must stop while the upload consumer is behind. Plaintext and decompressed buffers are wiped where the runtime permits and never persisted by the worker.

The server continues to store one contiguous S3 object whose non-final multipart parts are 16 MiB plus AES-GCM overhead. The final part may be smaller, as S3 permits. Range downloads continue to use fixed arithmetic and need no per-compression-frame or per-chunk offset table.

## Upload reservations and schema semantics

Quota checks become real reservations. The current check considers only `users.total_storage_bytes` and does not include other in-progress sessions, so concurrent uploads can each observe and consume the same free space. This feature must replace that check with an atomic transaction that adds committed usage and every active, unexpired upload reservation for the user before inserting a new upload session. Legacy sessions reserve their exact declared encrypted size. Format-2 sessions reserve their guaranteed maximum encrypted size.

Add `reserved_size_bytes` to `upload_sessions`. It is the maximum pre-padding encrypted stream accepted for that session and is never copied to `file_metadata`. Cancellation, expiry, failed storage initialization, and abandoned-session cleanup release the reservation by removing or terminally closing the session. Completion atomically removes the session from active reservation accounting while adding only the actual pre-padding encrypted size to `users.total_storage_bytes`.

Keep `total_size`, `total_chunks`, and `padded_size` as the actual finalized values. A format-2 session initializes them to zero or null as permitted by the migrated schema and fills them only when the client seals the stream. Do not temporarily put the reservation into `total_size`; existing code treats that field as exact and uses it for padding, range arithmetic, and completion validation.

Add `payload_format_version`, `encrypted_payload_metadata`, and `payload_metadata_nonce` to `upload_sessions` and `file_metadata`. Add nullable `encrypted_payload_manifest` to both so the format-2 manifest can be stored at seal and copied verbatim into the completed file record. Existing rows receive payload format 1 and null new ciphertext fields. No existing file, share, account, MFA record, billing record, or stored object is rewritten.

The server sees payload format, reservation size while the session exists, actual compressed encrypted size, chunk count, padded size, and the opaque lengths of the new encrypted metadata. It does not receive the original size as a dedicated plaintext field. The reservation bound will usually be close to the original size and therefore remains observable operational metadata during upload; this must be documented honestly.

## Format-2 upload state machine

Upload initialization validates payload format support, the opaque metadata pair, the reservation, and the normal FEK and ownership fields. It atomically reserves quota and creates an S3 multipart upload. For format 2, `total_size`, `total_chunks`, and padding are not yet final.

Ordinary format-2 chunk requests are sequential and contiguous. Every non-final encrypted body is exactly the configured transport plaintext size plus nonce and tag. The server verifies `X-Chunk-Hash`, enforces the cumulative reservation cap, uploads the part, and records its size and ETag. Retries of an already accepted index remain idempotent only when the hash matches. A gap, changed replay, body over the reservation, or extra chunk after seal is rejected with a stable error code.

After the compressor is finished but while the client still retains the final encrypted chunk, the client calls a new idempotent seal endpoint. The request supplies the actual compressed-stream size, actual pre-padding encrypted size, total chunk count, final encrypted chunk size and hash, and the opaque FEK-encrypted manifest. The server validates bounded encodings and arithmetic, checks that already uploaded parts plus the declared final part equal the declared actual size, verifies that actual size does not exceed the reservation, calculates padding from the actual size, and records the sealed values. A repeated identical seal succeeds; a changed seal conflicts.

The client then uploads the final chunk. The server requires its size and hash to match the sealed record, appends cryptographically random padding, and uploads it as the final S3 multipart part. Padding generation and upload must be streaming and must not allocate memory proportional to the padding size. This work must reconcile the current 16 MiB `maxPaddingPerChunk` guard with the percentage-based padding calculator, whose possible padding for a multi-gigabyte object can exceed that guard. The resulting rule must support the required 6 GB use case and remain bounded-memory.

The existing complete endpoint verifies the sealed chunk set, completes the multipart upload, writes `file_metadata`, changes committed quota by actual `total_size`, and makes retries idempotent for the same completed session. Seal, final-chunk upload, complete, status, and cancel all count as transfer requests for the session-family activity and one-file grace rules established by `docs/wip/auto-logout.md`.

## Download and decompression

New clients send a payload-format capability header on metadata and chunk requests. A new server accepts legacy clients for format-1 files but returns a stable `payload_format_unsupported` response before content bytes for a format-2 file when the client did not advertise version 2. This prevents an old client from decrypting zstd bytes and writing them as though they were the original file. A new CLI connecting to an older server detects the absence of compression capability and uploads format 1.

For format 2, the owner client unwraps the FEK, decrypts and validates the payload manifest, cross-checks it against the server metadata, and then downloads fixed encrypted chunks using the existing range shape. Each chunk is authenticated in full before any of its decrypted compressed bytes are passed to zstd. The streaming zstd decoder emits bounded output under backpressure to the existing File System Access, Service Worker, Blob fallback, CLI temporary-file, or offline-decrypt sink.

The decoder enforces the configured maximum window, the authenticated original output size, and an exact end-of-frame. It rejects trailing non-frame data, premature frame completion, output beyond the manifest size, output shorter than that size, unsupported dictionaries, unsupported profile values, or a plaintext SHA-256 mismatch. The SHA-256 remains the digest of the original decompressed file. Service Worker `Content-Length`, large-file warnings, progress based on logical bytes, and destination-space guidance use the authenticated original size rather than compressed transport size. Network progress may separately use encrypted bytes received.

The Blob fallback remains unsuitable for very large logical files even if the compressed object is small. Its warning threshold must therefore use original decompressed size. A highly compressible 20 GB file is still a 20 GB browser output.

## Sharing

Share creation decrypts the owner's payload metadata and payload manifest in addition to filename and plaintext digest. The encrypted share envelope gains an explicit payload format version, original logical size, compression profile identifier, and the existing filename, FEK, download token, and original plaintext SHA-256. The existing ambiguous `size_bytes` field is retained only for parsing old envelopes; new envelopes use an unambiguous `original_size_bytes` field. Go and TypeScript share-envelope parsers must support both shapes and cross-check version-2 values against the FEK-authenticated payload manifest.

The recipient enters the share password before any private metadata is displayed. After the envelope decrypts, the page shows the original decompressed size and uses it for warnings before Download is pressed. Public share metadata continues to expose only operational transport fields plus the opaque encrypted payload manifest and server-visible payload format. It does not expose original size.

Share creation requests declare the payload format outside the opaque envelope so the server can reject an old client attempting to create an incomplete share for a format-2 file. Old share recipients that do not advertise format 2 are refused before the first content chunk. Revocation, ticket issuance, access counting, and limits otherwise remain unchanged.

## `.arkbackup` export and offline recovery

Legacy payload-format-1 files continue exporting as `.arkbackup` version 2 so existing offline tools remain useful for every existing object. A compressed payload exports as `.arkbackup` version 3. Version 3 carries payload format, opaque payload metadata, the FEK-encrypted payload manifest, actual encrypted and padded sizes, and the existing owner metadata and FEK envelope. The S3 object is still copied verbatim and streamed without buffering.

`arkfile-client decrypt-blob` supports versions 2 and 3. It validates and authenticates a version-3 manifest before reading content chunks, excludes trailing server padding, decrypts format-2 chunks with the new AAD, streams decrypted compressed bytes through zstd, writes decompressed output to the existing temporary destination, verifies original size and SHA-256, and publishes only after success. Old clients reject outer bundle version 3 immediately, before producing an output file.

Backup discovery, batch decrypt, inspection, and integrity-manifest tooling must recognize both bundle versions. The local integrity manifest continues hashing complete `.arkbackup` bytes and requires no password. Inspection may show payload format and logical size only after the relevant encrypted metadata has been unlocked; its passwordless view must not invent a plaintext original size.

## User-visible size and accounting

`size_bytes` remains the actual pre-padding encrypted object-stream length and remains the user quota and projected billing value. `padded_size` remains the actual provider object length. Compression therefore benefits the operator and the user without charging for the reservation or the original logical size. Provider statistics and replication continue to use padded physical bytes.

After metadata unlock, owner clients may display both logical original size and occupied or billable size. Existing format-1 records without payload metadata derive original size from the legacy chunk formula. Account-level logical totals are calculated client-side from decrypted metadata; the server does not receive or aggregate original plaintext sizes.

Progress wording must distinguish source hashing, compression, encrypted upload bytes, decompression, and logical output. The user should be told when compression was bypassed because projected savings were below the threshold, but filenames, ratios tied to filenames, samples, and plaintext metadata must not enter logs.

## Privacy and security

Compression occurs before encryption and within one file only. No compression dictionary or history is shared across files, users, shares, metadata fields, or attacker-controlled and secret fields. This prevents cross-file compression contexts from becoming an oracle. The zstd stream contains file payload bytes only.

Compression changes length leakage. The server and storage provider observe compressed encrypted length instead of the old near-plaintext length, while the server also observes the temporary guaranteed reservation. The server can learn that compression was selected and may infer that a file was compressible. Fixed AEAD transport chunks avoid exposing a separate length for every source region. Server padding continues to obscure exact stored length from the storage provider but is calculated around compressed size.

Every encrypted transport chunk must authenticate before decompression. Decoder window and output limits are mandatory even though the stream is FEK-authenticated, because a malicious file owner can create a share intended to exhaust a recipient. Browser and CLI decoders reject dictionaries, oversized windows, unsupported frames, excess output, truncation, and trailing bytes. Fuzz tests cover payload manifests, bundle version 3 headers, and decoder-facing framed input.

No plaintext sample, original size, compression ratio, zstd error containing plaintext, or decompressed bytes are logged or sent to the server. Production debug output may report format version and aggregate byte counts already classified as operational metadata, but never filenames or sample contents.

## Backward compatibility and rollout

All schema changes are additive and receive idempotent in-place migrations in `runSchemaMigrations`. Existing `file_metadata` rows default to payload format 1. Existing active upload sessions are backfilled with payload format 1 and reservation equal to their current exact `total_size`. The migration does not invalidate sessions, files, shares, MFA settings, admin access, credits, subscriptions, or billing history.

Old clients can upload, download, share, and export format-1 files after the server update. They receive a clear unsupported-format error for format-2 content. New clients read both formats and fall back to format 1 when connected to a server that does not advertise compression. Compression is enabled only after both official clients and all owner, share, export, and offline recovery paths are complete.

Rollout uses `test-update.sh` on the populated test deployment, never a destructive deploy. Verify schema backfill, old-client format-1 behavior, new cross-client behavior, quota reservations, abandoned-session cleanup, shares, exports, offline restore, storage replication, and billing before `prod-update.sh`. Existing objects are not recompressed. Any future migration tool is a separately reviewed project with resumability, rollback, and user consent.

## Implementation order

First complete the dependency gate and the zstd prototype. Then lock the shared profile and payload-format bytes with cross-language fixtures. Implement manifest crypto, format-2 AAD, bounded browser worker and Go stream helpers, and unit tests before changing HTTP or schema behavior.

Next add additive schema migrations, atomic quota reservations, capability reporting, and the format-2 init, chunk, seal, final-part, complete, cancel, expiry, and retry state machine. Keep the legacy state machine intact and selected strictly by payload format. Prove S3 multipart sizing and padding behavior with storage mocks before wiring clients.

Then update upload and owner download in TypeScript and Go together. Cross-client tests must prove browser upload with CLI download and CLI upload with browser download. Only after owner round trips pass should sharing and `.arkbackup` version 3 be enabled. UI size presentation, documentation, and full e2e coverage follow before the feature flag or capability is enabled by default.

## Testing and validation

Go unit tests cover compression-bound and encrypted-reservation arithmetic, overflow rejection, atomic concurrent reservations, release on every terminal path, actual-size quota commit, format-1 migration defaults, format-2 state transitions, sequential chunks, idempotent retries, exact-multiple output, one-chunk output, reservation overflow, seal conflicts, final-part padding, multipart minimums, and completion retries.

Shared cryptographic tests pin format-2 chunk AAD and payload-manifest AAD, Go-to-TypeScript and TypeScript-to-Go manifest decrypt, standard zstd frame interoperability, malformed manifest rejection, original-size limits, unsupported profiles, truncated and trailing streams, excessive window requests, and deliberate AEAD corruption before decompression.

TypeScript tests use dependency-injected worker and network boundaries to cover sample decisions, bounded queues, backpressure, cancellation, worker failure, session expiry during compression and upload, final-chunk lookbehind, owner and shared decompression, Service Worker and Blob content length, logical-size warnings, and secret-buffer disposal. Go CLI tests mirror upload, download, share, offline bundle, cancellation, temporary-output cleanup, and cross-format behavior.

Handler and model tests cover capability negotiation, old-client refusal on format 2, opaque metadata validation, share creation version matching, public metadata privacy, bundle versions, reservation accounting with multiple simultaneous sessions, expiry cleanup, and no plaintext original-size field in API responses. Admin storage and billing tests prove actual compressed bytes, not reservation or logical bytes, drive quota and projected billing.

End-to-end coverage creates compressible, incompressible, mixed, account-password, and custom-password files. It proves bypass and compressed paths, browser and CLI interoperability, duplicate rejection before compression, owner download, shared recipient preview and download, `.arkbackup` export and offline restore, quota release, cancellation, retries, and raw-API privacy canaries. Playwright covers compression progress, logical size display, shared-file preview before Download, bounded-memory streaming behavior where observable, and Blob warnings based on decompressed size.

After code and unit tests are complete, the developer runs the workflow required by `AGENTS.md`: `dev-reset.sh`, then `e2e-test.sh`, then `e2e-playwright.sh`. The coding agent may run the Go and Bun unit suites but must not invoke deployment or e2e scripts.

## Out of scope

This work does not add server-side compression, server-readable original sizes, compression dictionaries, cross-file compression contexts, server-side content inspection, storage-object deduplication, multiple metadata rows pointing to one object, FEKs derived from content, recompression of existing objects, random-access plaintext reads, partial extraction, or resumable decompression from an arbitrary midpoint. It also does not change password KDFs, OPAQUE, owner FEK envelope version 2, share-password derivation, or the plaintext SHA-256 definition.

## Files to add

- `docs/wip/compression.md` -- this plan
- `crypto/compression-params.json` -- embedded payload-format, zstd, sampling, threshold, window, and transport limits
- `crypto/payload_format.go` -- shared profile parsing, checked size arithmetic, format-2 AAD/manifest encoding, encryption, validation, and constants
- `crypto/payload_format_test.go` -- bounds, manifest, AAD, corruption, and profile tests
- `crypto/testdata/payload-format-v2.json` and associated small binary fixtures -- cross-language manifest and zstd interoperability vectors
- `models/upload_reservation.go` and `models/upload_reservation_test.go` -- atomic active-session reservation and release accounting
- `models/file_payload_test.go` -- payload-format defaults, projections, and original-size derivation coverage
- `client/static/js/src/crypto/payload-format.ts` -- browser profile, manifest, checked-size, and format validation
- `client/static/js/src/crypto/zstd-stream.ts` -- bounded page-side worker wrapper and backpressure
- `client/static/js/src/workers/zstd-worker.ts` -- locally built streaming zstd compression and decompression worker
- `client/static/js/src/__tests__/payload-format.test.ts` -- shared fixture, arithmetic, manifest, and malformed-input tests
- `client/static/js/src/__tests__/zstd-stream.test.ts` -- bounded queue, cancellation, finalization, and backpressure tests
- `cmd/arkfile-client/payload_stream.go` and `cmd/arkfile-client/payload_stream_test.go` -- CLI sampling, streaming zstd, fixed transport chunking, manifest, and decompression
- `handlers/upload_reservation_test.go` -- concurrent reservation, release, cap, and actual commit coverage
- A pinned zstd WASM build script and source-integrity metadata under `scripts/setup/` if the selected browser implementation requires a separately built WASM artifact

## Files to modify

- `database/unified_schema.sql` -- payload-format, reservation, opaque payload metadata, manifest, and format-2 upload-session fields
- `main.go` -- idempotent migrations and active-session backfill
- `go.mod` and dependency metadata generated by the selected Go zstd implementation
- `bun.lock` and `client/static/js/package.json` if the selected browser implementation is packaged through Bun
- `crypto/chunking-params.json` and `crypto/chunking_constants.go` -- clarify transport-chunk semantics without changing legacy values
- `crypto/aad.go`, `crypto/aad_test.go`, and shared AAD fixtures -- permanent payload metadata, manifest, and format-2 chunk domains
- `crypto/share_kdf.go`, `crypto/share_kdf_test.go`, and `crypto/share_envelope_conformance_test.go` -- original size and payload format in new share envelopes with legacy parsing
- `models/file.go`, `models/file_chunk_count_test.go`, and `models/file_list_cursor_test.go` -- new fields, default format, projections, transport arithmetic, and client metadata
- `models/user.go` and `models/user_test.go` -- committed actual storage updates where reservation finalization changes call sites
- `billing/effective.go` and billing tests -- quota availability including active reservations
- `handlers/uploads.go` and `handlers/uploads_test.go` -- format-2 init, chunks, seal, final part, padding, completion, cancellation, expiry, and legacy preservation
- `handlers/downloads.go` and relevant handler tests -- capability checks and format-aware metadata while retaining fixed ranges
- `handlers/files.go` and `handlers/files_test.go` -- opaque payload fields and format in owner metadata/list responses
- `handlers/file_shares.go` and `handlers/file_shares_test.go` -- format-aware share creation, public metadata, capability checks, and recipient chunk path
- `handlers/export.go` and `handlers/export_rotation_test.go` -- bundle version 3 metadata and unchanged streaming payload export
- `handlers/config.go` and `handlers/route_config.go` -- compression profile/capability endpoint and seal route
- `handlers/admin_task_runner.go` and its tests -- abandoned-session cleanup and reservation release
- `handlers/payments_test_helpers.go` and every test-local schema or sqlmock column list that defines `file_metadata`, `upload_sessions`, or file projections
- `utils/padding.go` and its tests -- bounded streaming-compatible padding calculation and generation for the final multipart part
- `client/static/js/src/crypto/constants.ts` -- embedded safety floors and compression config loading
- `client/static/js/src/crypto/aad.ts` and `client/static/js/src/__tests__/aad.test.ts` -- format-2 AAD and fixtures
- `client/static/js/src/files/upload.ts` and upload tests -- sample retention, decision, reservation, streaming worker, fixed output chunks, seal, retry, cancellation, and progress
- `client/static/js/src/files/streaming-download.ts`, `client/static/js/src/files/download.ts`, `client/static/js/src/files/download-integrity.ts`, and their tests -- manifest-first validation, decompression, logical lengths, hashing, and warnings
- `client/static/js/src/files/sw-streaming-download.ts`, `client/static/js/src/sw-download.ts`, and Service Worker tests -- authenticated original `Content-Length`, cancellation, and decompressed stream accounting
- `client/static/js/src/files/list.ts` and list tests -- logical versus occupied sizes after metadata unlock
- `client/static/js/src/files/share.ts`, `client/static/js/src/shares/share-creation.ts`, `client/static/js/src/shares/share-crypto.ts`, `client/static/js/src/shares/share-access.ts`, and share tests -- format-aware envelopes, original-size preview, manifest cross-check, and recipient decompression
- `cmd/arkfile-client/crypto_utils.go` and `cmd/arkfile-client/crypto_utils_test.go` -- format-aware chunk crypto and checked size helpers
- `cmd/arkfile-client/commands.go`, `cmd/arkfile-client/main.go`, `cmd/arkfile-client/dedup.go`, and upload/download tests -- capability negotiation, sampling after dedup, reservations, seal, streaming zstd, logical progress, and legacy fallback
- `cmd/arkfile-client/offline_decrypt.go`, `cmd/arkfile-client/offline_decrypt_batch.go`, `cmd/arkfile-client/bundle_fixture_test.go`, `cmd/arkfile-client/offline_decrypt_test.go`, and batch tests -- bundle version 3 validation and streaming restore
- `cmd/arkfile-client/backup_manifest.go` and `cmd/arkfile-client/backup_manifest_test.go` -- discovery and verification of bundle versions 2 and 3
- `cmd/arkfile-client/export.go` and export tests -- version-aware bundle handling and user-visible stored/logical sizes where reported
- `scripts/setup/build-config.sh`, `scripts/setup/build.sh`, and `scripts/setup/build-client.sh` -- integrate and verify the pinned zstd dependency without changing the established build entry points
- `scripts/dev-reset.sh`, `scripts/local-deploy.sh`, `scripts/prod-deploy.sh`, `scripts/test-deploy.sh`, and shared deploy helpers only if the selected locally built WASM artifact must be installed or verified by those existing workflows
- `scripts/testing/e2e-test.sh`, `scripts/testing/e2e-playwright.ts`, `scripts/testing/offline-integrity-test.sh`, and `scripts/testing/online-integrity-test.sh` -- compressed, bypass, share, bundle-v3, cross-client, quota, and corruption cases
- `docs/api.md` -- capability, upload reservation/seal, payload fields, errors, share fields, and bundle version
- `docs/security.md` -- compression threat model, observable lengths/reservations, manifest and AAD, decoder limits, and accounting classification
- `docs/testing.md` -- prototype, unit, cross-client, e2e, Playwright, and populated-update coverage
- `docs/setup.md` and `docs/wip/cli-builder.md` -- pinned zstd build prerequisites and standalone client packaging if required
- `docs/user-faq.md` and `client/static/faq.html` -- matching prose Q&A on automatic compression, logical versus charged size, and unchanged client-side encryption

## Remaining open questions

- Which pinned browser and Go zstd implementations satisfy the prototype gate, and does the browser use an upstream C-to-WASM build or a reviewed package already suitable for streaming compression and decompression?
- Does level 1 or level 3 provide the best measured balance on constrained mobile hardware, and what maximum decoder window should be accepted?
- What minimum file size, total sample budget, sample placement, and minimum projected percentage or absolute-byte saving should select format 2?
- Should the first format use one continuous zstd frame as proposed, or do measured recovery needs justify independently finalized frames at a larger interval while still packing their output into fixed encryption chunks?
- Should a user whose guaranteed reservation exceeds free quota be rejected before upload, or may an explicitly warned upload reserve only the remaining quota and risk a clean mid-stream failure if compression is worse than estimated?
- Should reservation size be rounded to coarse buckets to reduce how closely it reveals original size during an active compressed upload, accepting more false quota rejections?
- What exact status code should represent `payload_format_unsupported`, and should capability negotiation use a request header, a versioned endpoint, or both?
- Should `encrypted_payload_metadata` be one extensible canonical binary structure or canonical JSON, and which fields beyond original size and format belong in its first version?
- Should the FEK-encrypted payload manifest duplicate the plaintext SHA-256 already stored in Account-Key-encrypted metadata and share envelopes, or bind only sizes, profile, and chunk count?
- What is the final bounded-memory padding rule for multi-gigabyte objects, given the current percentage calculator can produce more padding than the current 16 MiB final-chunk cap permits?
- Should completed upload-session rows clear `reserved_size_bytes` immediately or retain it for a short operational audit window before cleanup?
- How should the UI present logical and occupied sizes per file and at vault-total level without confusing storage quota, provider padding, and decompressed output size?
- Should users be able to disable compression per upload, or should the measured automatic bypass remain the only control?
- Should compressed uploads initially be guarded by a server configuration flag during test rollout, even after both official clients support the format?
- What representative corpus and constrained device become the release benchmark, and what minimum storage saving and maximum throughput or memory regressions constitute the ship threshold?
