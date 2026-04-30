# General Enhancements

## Standalone improvements worth considering for Arkfile

Each item below is a self-contained idea, evaluated on its own merits.

### 1. AAD binding on every per-file encrypted-metadata field

Today, only share envelopes use AES-GCM Additional Authenticated Data (AAD). The per-file metadata fields stored alongside each file -- encrypted filename, encrypted content hash, wrapped File Encryption Key -- are encrypted with AES-GCM but without AAD. This means a buggy or malicious code path that swaps these blobs between two of the user's own files (or between two users) would silently decrypt with the wrong identity bindings: wrong filename displayed, wrong integrity check passed, wrong key unwrapped. Binding each ciphertext to a tuple like `(file_id, field_tag, username)` via AAD turns every such swap into a hard, specific decryption error rather than a quiet wrong-data display. Small footprint, high actual threat reduction.

### 2. Pre-flight storage-quota endpoint

A small authenticated endpoint that returns the user's storage summary -- committed bytes, in-flight bytes, limit, and available space. Today this information is only available as a side-effect of login responses, file-list responses, or upload-completion responses, none of which is the right shape when a client wants to ask "do I have room for this?" before doing work. A purpose-built endpoint lets clients fail fast with a precise message ("you need X more MB") instead of mid-stream.

### 3. In-progress-aware quota accounting

The current quota check counts only finalized file bytes. A user with several abandoned-but-not-cleaned-up upload sessions can over-commit storage temporarily and then hit a confusing mid-stream failure. Summing the deterministically-known padded size from both finalized files and in-progress sessions produces an exact quota number, not an estimate, and removes a corner case where the same user could repeatedly start large uploads to occupy more storage than allotted.

### 4. Server-side cap on concurrent in-progress upload sessions, with lazy stale-session cleanup

There is currently no cap on how many simultaneous upload sessions a single user can hold open. A buggy client (or a hostile one with valid credentials) can open arbitrary numbers of sessions, exhaust their own storage, and starve themselves of the ability to complete anything. A small per-user cap, plus opportunistic marking of expired sessions as abandoned in the same SQL path, removes a real abuse and footgun surface for almost no code.

### 5. Tightened residency contract for the in-memory Account Key

The Account Key in browser memory is the worst-case blast-radius asset for any future XSS -- it can decrypt every metadata blob and unwrap every account-wrapped FEK. The residency window today is implicit: cleared on logout and inactivity timeout. An explicit, documented contract -- wipe on logout, on JWT session expiry, on refresh-token rotation, on full-document navigation, and on inactivity timeout, with any extension of the window requiring an explicit user opt-in -- converts that implicit policy into something users and contributors can reason about. Aligns the in-memory blast-radius window with the auth window.

### 6. Decrypted plaintext metadata stays in memory, never in `sessionStorage`/`localStorage`/IndexedDB

Any time the frontend caches decrypted metadata (filenames, integrity hashes, anything the user encrypted), it should live in a module-scoped JavaScript `Map` that dies on tab close or full page reload -- never in a storage API readable by other scripts on the page. The cost is having to re-decrypt on full page reload. The benefit is that the XSS blast radius for decrypted plaintext is bounded by the lifetime of the current document. Worth codifying as the standing policy for any future "let's cache decrypted X" idea.

### 7. Treat refresh-token rotation as a sensitive-cache wipe trigger

Whenever the JWT is rotated or the refresh token is consumed, every in-memory cache holding decrypted material should be wiped along with the auth state. Today the auth context can roll over while sensitive caches persist. Aligning the two windows is a small policy change that keeps the in-memory blast radius coupled to the auth window rather than to a separate inactivity timer.

### 8. Closing the schema-evolution gap

The current `unified_schema.sql` is `CREATE TABLE IF NOT EXISTS`-only and there is no migration framework. Adding a column to an existing table silently no-ops on a populated database -- every column-addition project would either force a wipe or have to invent its own one-off mechanism. A minimal column-evolution layer (compare `PRAGMA table_info(...)` against a Go-side manifest, emit conditional `ALTER TABLE ... ADD COLUMN` for known additions) would unblock every future additive schema change. Doing this once removes the "wipe to add a column" cost from every future feature.

### 9. Standardized structured error responses with stable string codes

Today's HTTP error responses are a mix of plain strings and ad-hoc shapes. Converging on a single body shape -- `{"error": "<stable_code>", "message": "<text>", "details": {...}}` -- and a small registry of stable codes lets clients switch on the code rather than parsing English text. This makes the TS frontend and the Go CLI both more robust to message changes and lets either of them surface localized or context-appropriate messages without coordination with the server. Worth doing once and backfilling existing handlers gradually.

### 10. Sequential multi-file upload via the existing per-file pipeline

The browser file input and the CLI upload command are both single-file today. The server pipeline is already per-file, so allowing a client to queue N files and walk through them sequentially is a small client-side change with zero crypto-protocol risk. Adding the multi-select attribute to the web input, a directory walker on the CLI, and a sequential loop with per-file progress and partial-failure summary covers a long-standing real user need.

### 11. Per-file partial-failure handling as a standing pattern

For any operation that touches more than one item, the right semantic is "continue past per-file failures, summarize at the end" with a clear stop-on-fatal list (auth expired, quota exceeded, account disabled). Codifying this pattern -- once, with a small set of fatal-vs-skippable categories -- sets the right expectation for every future batch-shaped operation (batch download, batch delete, batch share, batch export, etc.).

### 12. Per-file cancellation surfaced as a first-class user action

The cancel-upload endpoint exists today but is rarely surfaced in the UI. Making "cancel this in-progress operation" an obvious, always-available action -- both as a per-row button in the web UI and as a clean Ctrl-C-during-loop behavior in the CLI -- makes the system feel responsive instead of opaque. The server side is already there; this is purely UX work.

### 13. Pure-comment clarifications on misleading existing names

Some persisted columns and struct fields have names that mislead. The most prominent example is a column with an `encrypted_` prefix that actually stores a server-computed plaintext hash over already-encrypted data. A short clarifying comment on the field, a short header comment on `models/user.go` documenting that username is an immutable identifier used as a stable key across many tables (and as part of cryptographic bindings), and similar small annotations elsewhere all cost nothing and prevent recurring "wait, why is the server reading that?" confusion.

### 14. Documented self-containment of the share flow

The share flow's storage tables and key derivation are independent of the owner-side per-file metadata: shares carry their own wrapped File Encryption Key under a Share Key derived from the share password, and share metadata lives in a recipient-side envelope rather than the owner's columns. This is a non-obvious property of the codebase that protects future contributors from accidentally entangling the two flows. Writing it down somewhere durable (security docs or a header comment on the share handlers) preserves a real piece of architectural knowledge that took reading-through to confirm.

### 15. Honest documentation of what the server can still observe

Even with strong client-side encryption, the server passively observes things like the timing pattern of upload-session creation, the size distribution of an upload batch, the count of files belonging to a user, and the rate of share-download attempts. Documenting these "we cannot hide this" facts in `docs/privacy.md` as standing documentation sets correct expectations for users reasoning about the threat model and prevents the appearance of overclaiming. It also helps future contributors not introduce features that quietly worsen the picture without anyone noticing.

### 16. "Encrypt and decrypt paths ship in the same change" as a contributor convention

For any cryptographic-format change, the encrypt path and the decrypt path should land together -- never an intermediate revision where a new field can be written but not read, or read but not written. This rule prevents the class of bug where a deployed client can produce ciphertexts that no installed client (including itself, after a refresh) can decrypt. Worth codifying in the contributor guide so it applies to every future format change, not just the next one someone happens to think of.

### 17. Bucketed length padding for short, sensitive metadata strings

Variable-length encrypted strings leak length to a passive server observer. For short fields where the variation reveals something (a short hint, a future short-text annotation, etc.), padding the plaintext to a small bucket size before encryption (with the pad bytes being a value that's forbidden in canonical input, so they strip unambiguously on decrypt) reduces the leak from "exact byte length" to "bucket index." Establishing this as a standing pattern -- with a small documented bucket size per field type -- means each future short-string addition gets the protection without a fresh design discussion.

### 18. Cross-language byte-identity enforced by shared test vectors

Anywhere a wire-format byte sequence has to be produced identically by both the Go and TypeScript clients (key derivation inputs, cryptographic bindings, canonicalization, share envelope construction, etc.), the right enforcement mechanism is a single JSON file of test vectors that both implementations load and assert against, rather than two independently-written test suites that may drift. Adopting this as a standing convention -- anything wire-format-critical gets vectors before either implementation lands -- prevents a class of subtle, hard-to-diagnose cross-client bugs.

### 19. Tamper E2E tests as part of every cryptographic-binding change

Any time a field gains a cryptographic binding (AAD, signed envelope, etc.), the e2e test suite should grow a paired tamper test: directly modify the stored ciphertext or its binding inputs in the database, then assert that the client surfaces a clear, specific decryption-failure error in every read path that touches that field. Codifying this as a checklist item ("if you bind a field, add the tamper test") prevents the binding wiring from silently degrading over time as code is refactored.

### 20. Honest pre-release deploy story with a beta-user notice template

For any change that makes existing data undecryptable or otherwise requires a wipe, the right deploy story includes (a) an explicit choice between fresh-deploy and update scripts, with reasoning, (b) a pre-deploy notice to beta testers that names exactly what they will lose and what they need to do, and (c) a post-deploy smoke checklist run before reopening the beta. Keeping a reusable template for this notice, and a checklist for the post-deploy verification, makes the operational cost of a wipe predictable and reduces the temptation to invent an intricate dual-format compatibility scheme purely to avoid the conversation. Operational honesty about pre-release cost builds trust with beta users at a stage where there's nothing else to build trust on.

### 21. Client-side encrypted, client-controlled optional tags on user-owned files

Files in a user's vault are otherwise opaque to the server, identified only by an internal file ID and ordered by upload date. As the number of files grows, finding a specific one becomes increasingly tedious. A small, client-side organization mechanism -- optional free-form tags attached to each file -- would address this without introducing any structural changes to how files are stored, named, or referenced. Tags are purely a convenience for the file owner and never exposed to share recipients or the server in plaintext.

Each file may carry up to 16 user-chosen tags, each tag a UTF-8 string of 1 to 64 bytes after NFC normalization, with control characters and the NUL byte forbidden. The tag list for a file is serialized client-side as a short JSON array of strings, encrypted with the user's Account Key under AES-GCM with AAD binding to `(file_id, "tags", username)` to prevent cross-file or cross-user tag-blob substitution, and stored on the file's metadata row as a single ciphertext column plus its nonce. The server stores and returns these bytes as opaque blobs and never sees the tag list in plaintext; it cannot enumerate, sort, search, or filter by tag at any layer. The plaintext is bucket-padded to a small fixed size before encryption (in the same spirit as item 17, "Bucketed length padding for short, sensitive metadata strings") so the ciphertext length leaks only a coarse "few tags" vs. "many tags" signal rather than an exact count or total length.

Tags can be set at upload time (a single text input on the upload form, comma-separated; CLI flag `--tag` repeatable) and updated at any later time via a small endpoint that accepts a fresh ciphertext-and-nonce pair for an existing file ID and replaces the stored values atomically. Because the server never reads the plaintext, the update path requires no validation beyond ownership, ciphertext format, and the standard AAD round-trip on the next read. There is no schema for "the set of all tags" -- that set exists only client-side, computed lazily by decrypting each file's tag blob in the listing view and forming the union, and surfaced in the UI as a row of clickable filter chips above the file list. Filtering is purely a client-side operation against the in-memory decrypted metadata cache (item 6), so it imposes no new server cost and no new server-observable query patterns.

This stays well within Arkfile's privacy posture: the server learns nothing about file organization beyond what it already observes (existence, size, upload time), and an attacker with access to the database sees only a small additional ciphertext blob per file with the same AAD-bound integrity guarantees as the existing per-file metadata fields. Cost is small -- one column pair on the file metadata table, one encrypt-and-decrypt path mirrored across the TS frontend and the Go CLI, one update endpoint, one filter UI, and a documented limit on tag count and length so future contributors don't drift the bounds. Strictly opt-in: a user who never adds a tag is unaffected, and the column simply stays NULL.
