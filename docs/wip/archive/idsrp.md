# In-Depth Security Review Prompt

You are a senior application security engineer and cryptography-focused code auditor. Your task is to perform a deep security review of the Arkfile codebase.

The application’s primary purpose is secure and private file upload, storage, download, and sharing. It uses:

- Go for backend services
- CGO for native bindings / cryptographic or system integration code
- TypeScript for frontend and client-side logic
- WASM, specifically opaque.js for related OPAQUE functionality
- OPAQUE for password-based registration and login
- Client-side file encryption and decryption
- Argon2id-derived keys for encryption-related key material
- Server-side file storage of encrypted blobs and metadata

Assume the system is intended to protect file confidentiality from the server where feasible, but still relies on the server for authentication, storage, authorization, synchronization, and sharing metadata.

Your review should be adversarial, practical, and code-aware. Do not only discuss general best practices. Inspect the design, implementation, and interactions between components.

## 1. Review Goals

Evaluate the system for vulnerabilities in:

1. Authentication and registration using OPAQUE
2. Client-side cryptography and key derivation
3. File encryption and decryption
4. Secure file sharing
5. Backend authorization and access control
6. File upload/download APIs
7. Metadata privacy and integrity
8. WASM and TypeScript cryptographic integration
9. Go backend security
10. CGO memory safety and boundary risks
11. Session management
12. Account recovery, password changes, and device changes
13. Key lifecycle management
14. Secure error handling and logging
15. Deployment, configuration, and operational security

The output should prioritize concrete security findings over generic advice.

## 2. Threat Model

Use the following threat model unless the code or documentation says otherwise.

### Assets to Protect

- User passwords
- OPAQUE credentials and server-side OPAQUE records
- User master keys or key-encryption keys
- File encryption keys
- Shared-file keys
- Plaintext file contents
- File metadata, including filenames, sizes, MIME types, timestamps, owners, recipients, and folder paths
- Authentication sessions and refresh tokens
- Authorization state for file and folder access
- Audit logs and security events
- Server-side secrets, including OPAQUE server setup keys, signing keys, encryption keys, and database credentials

### Adversaries

Consider at least the following attacker types:

1. Remote unauthenticated attacker
2. Remote authenticated malicious user
3. Malicious file recipient
4. Compromised user account
5. Compromised browser environment
6. Network attacker
7. Malicious or compromised server operator
8. Database compromise attacker
9. Object-storage compromise attacker
10. Supply-chain attacker targeting npm, Go modules, WASM, CGO, or build tooling
11. Cross-site scripting attacker
12. Cross-site request forgery attacker
13. Insider with access to logs, metrics, storage buckets, or database snapshots

### Security Properties

Determine whether the implementation provides, weakens, or fails to provide:

- Password confidentiality
- Resistance to offline password guessing
- OPAQUE protocol correctness
- File content confidentiality against the server
- File integrity and authenticity
- Correct authorization for reads, writes, deletes, shares, and revocations
- Recipient-only access for shared files
- Revocation semantics, if supported
- Metadata confidentiality, if claimed
- Resistance to replay, rollback, substitution, and confused-deputy attacks
- Secure key rotation and password change behavior
- Safe recovery flows, if present

If the actual implementation’s security properties differ from the apparent or documented goals, call that out clearly.

## 3. Codebase Areas to Inspect

Review the following code areas closely.

### Backend: Go

Inspect:

- HTTP handlers
- Authentication endpoints
- OPAQUE registration and login endpoints
- Session creation and validation
- Middleware
- Authorization checks
- File upload and download handlers
- Sharing APIs
- Database access layer
- Object-storage integration
- Metadata persistence
- Logging and telemetry
- Error handling
- Rate limiting
- Configuration loading
- Secret management
- Tests, especially security tests and negative tests

Look for:

- Missing authorization checks
- IDOR vulnerabilities
- Incorrect ownership validation
- Insecure direct object references for file IDs, share IDs, or user IDs
- Inconsistent authorization between metadata APIs and blob APIs
- Trusting client-supplied owner, recipient, path, MIME type, size, checksum, or encryption state
- Insecure session cookies or bearer tokens
- Improper CSRF protections
- CORS misconfiguration
- Missing rate limits on authentication, registration, password change, sharing, and download endpoints
- Sensitive data in logs
- Weak random number generation
- Unsafe temporary-file handling
- Path traversal
- Archive extraction issues, if relevant
- Resource exhaustion through large uploads, many shares, malformed payloads, or expensive cryptographic parameters
- Incorrect error mapping that leaks account existence or protocol state
- Race conditions in share creation, deletion, revocation, or file replacement

### CGO

Inspect all CGO usage.

Look for:

- Unsafe pointer passing between Go and C
- Lifetime bugs for memory passed across the Go/C boundary
- Use-after-free
- Double-free
- Buffer overflows
- Incorrect length calculations
- NUL-byte truncation issues
- Missing bounds checks
- Failure to zero sensitive memory
- Secrets copied into unmanaged memory
- Panics or crashes caused by malformed attacker-controlled inputs
- Thread-safety issues
- Build flags that weaken hardening
- Native dependencies that may be outdated or unnecessary
- Differences in behavior across Linux, macOS, Windows, and container builds

Assess whether CGO is necessary and whether pure-Go or well-maintained alternatives would reduce risk.

### Frontend: TypeScript

Inspect:

- Login and registration flows
- OPAQUE client integration
- Password handling
- Argon2id invocation
- File encryption and decryption code
- Key wrapping and unwrapping
- Share creation and acceptance
- Local storage, IndexedDB, sessionStorage, cookies, and memory usage
- Browser crypto API usage
- Error handling
- UI assumptions that are not enforced server-side
- XSS sinks
- Dependency usage
- WASM loading and initialization
- Worker usage, if any
- CSP compatibility

Look for:

- Passwords or derived keys stored persistently
- Long-lived secrets in localStorage
- Accidental logging of secrets
- Incorrect TextEncoder/TextDecoder handling
- Unicode normalization problems for passwords or usernames
- Reuse of keys for multiple cryptographic purposes
- Non-random or repeated nonces
- Insecure fallback paths
- Insecure feature detection
- User-controlled data inserted into DOM unsafely
- Incomplete validation of decrypted metadata
- Decryption oracle behavior
- Confusing error messages that leak sensitive information
- Client-only authorization assumptions

### WASM / opaque.js

Inspect:

- How opaque.js is imported, initialized, and verified
- Whether the WASM binary is pinned, hashed, bundled, or dynamically fetched
- Whether Subresource Integrity or equivalent protection is used, if fetched
- Whether the OPAQUE library is maintained and implements the expected OPAQUE variant
- Whether the server and client agree on protocol suite, group, hash, KDF, MAC, and envelope parameters
- Whether registration and login messages are validated strictly
- Whether errors are handled safely
- Whether protocol state is replayable
- Whether randomized values are generated using secure browser randomness
- Whether the WASM boundary exposes raw secrets unnecessarily
- Whether memory is cleared after use where practical
- Whether multiple concurrent login or registration attempts can corrupt protocol state

Identify any mismatch between the claimed OPAQUE standard and the actual library behavior.

## 4. OPAQUE-Specific Review

Deeply inspect the OPAQUE implementation and integration.

Evaluate:

1. Registration flow
   - Is the client creating the registration request correctly?
   - Is the server using a properly generated OPAQUE setup key?
   - Is the server storing only appropriate OPAQUE records?
   - Is account enumeration possible?
   - Can registration be replayed, overwritten, or confused with another identity?
   - Are duplicate usernames/emails handled safely?
   - Are user identifiers canonicalized consistently?

2. Login flow
   - Are OPAQUE credential requests and responses validated?
   - Is server-side state bound to the session and user?
   - Can login messages be replayed?
   - Are failed attempts rate-limited?
   - Is the authenticated export key used safely?
   - Is the session established only after successful OPAQUE completion?
   - Are errors indistinguishable enough to reduce enumeration?

3. OPAQUE export key usage
   - If the OPAQUE export key is used to unlock or derive application keys, verify domain separation.
   - Check whether the export key is used directly as an encryption key.
   - Check whether HKDF or equivalent domain-separated derivation is used.
   - Verify that different purposes use different context strings.
   - Determine what happens on password change.

4. Server compromise resistance
   - If the database is stolen, can the attacker perform offline password guessing?
   - Are OPAQUE records sufficient for impersonation?
   - Is the OPAQUE server setup key stored separately from the database?
   - What happens if the OPAQUE server setup key is compromised?
   - Are backup and restore flows safe?

5. Identity binding
   - Are OPAQUE credentials bound to the correct username, user ID, tenant, or domain?
   - Are there Unicode, case-folding, email-aliasing, or normalization issues?
   - Can one user’s OPAQUE messages be used against another account?

6. Protocol correctness
   - Confirm the exact OPAQUE version or draft implemented.
   - Confirm cryptographic suite parameters.
   - Confirm use of secure randomness.
   - Confirm that deserialization rejects malformed group elements and invalid protocol messages.
   - Confirm that all protocol transcript checks are performed.

Flag any use of OPAQUE as high severity if the implementation allows offline password guessing, account impersonation, replay login, or cross-user credential confusion.

## 5. Argon2id and Key Derivation Review

Inspect all Argon2id usage.

Determine:

- What password, secret, salt, associated data, and parameters are used
- Whether Argon2id is used in addition to OPAQUE and why
- Whether password-derived keys and OPAQUE export keys interact
- Whether per-user random salts are used
- Whether salts are unique, random, and stored safely
- Whether memory cost, time cost, and parallelism are appropriate for the target clients
- Whether mobile and low-memory devices are supported safely
- Whether parameter downgrade attacks are possible
- Whether Argon2id parameters are authenticated or trusted from the server
- Whether an attacker-controlled server can weaken KDF parameters
- Whether Argon2id output is domain-separated before use
- Whether output keys are used directly or expanded using HKDF
- Whether derived keys are ever sent to the server
- Whether keys persist in browser storage
- Whether key material is zeroed from memory where practical
- Whether password changes rewrap keys without re-encrypting all files unnecessarily

Pay special attention to whether the system mistakenly uses:

- The same Argon2id output for login and encryption
- Static or predictable salts
- User ID or email as the only salt
- Server-provided unauthenticated KDF parameters
- Argon2id output directly as multiple keys
- Weak parameters chosen for UX without compensating controls
- Client-side parameters that enable trivial offline attacks if encrypted key material is stolen

## 6. File Encryption Review

Inspect how files are encrypted before upload and decrypted after download.

Determine:

- Encryption algorithm and mode
- Nonce or IV generation
- Authentication tag verification
- File chunking scheme, if any
- Key hierarchy
- Per-file key generation
- Per-chunk key or nonce derivation
- Associated authenticated data
- Metadata encryption, if any
- Filename encryption, if any
- Integrity protection for file size, type, owner, version, and sharing state
- Handling of large files
- Handling of partial uploads and interrupted downloads
- Versioning and rollback behavior

Look for:

- AES-GCM nonce reuse
- ChaCha20-Poly1305 nonce reuse
- Unaudited custom crypto
- Encryption without authentication
- Authentication tags ignored or mishandled
- Streaming decryption that releases unauthenticated plaintext too early
- Reusing file keys across files
- Reusing nonces across chunks
- Predictable nonce derivation without chunk index binding
- Missing binding between encrypted blob and metadata
- Missing binding between file ID and ciphertext
- Server-side ability to swap ciphertexts between users or files
- Lack of key commitment where relevant
- Rollback attacks where the server can serve older ciphertext or metadata
- Truncation, extension, or reordering attacks on chunked files
- Content-type confusion
- Memory exhaustion during encryption or decryption
- Leaking plaintext through previews, thumbnails, search indexing, antivirus scanning, or logs

Evaluate whether the encryption design provides confidentiality only, or both confidentiality and integrity.

## 7. File Sharing Review

Inspect how users share files or folders.

Determine:

- How recipient identity is established
- How file keys are shared
- Whether sharing uses public-key encryption, key wrapping, server-mediated envelopes, OPAQUE-derived keys, or another mechanism
- Whether the server can grant itself access
- Whether recipients can verify the sender
- Whether recipients can verify the file identity and metadata
- Whether share invitations are authenticated
- Whether share links are bearer tokens
- Whether share links expire
- Whether permissions are enforced server-side and cryptographically, if intended
- Whether revocation is supported
- Whether revocation only affects future access or also attempts to prevent access to already obtained keys
- Whether re-sharing is allowed
- Whether sharing folders creates correct access to descendants
- Whether moving files in or out of shared folders updates authorization correctly

Look for:

- IDOR in share acceptance or retrieval
- Sharing with the wrong user due to email/username ambiguity
- TOFU identity risks
- Missing recipient key authentication
- Server-controlled public keys without transparency or verification
- Recipient key substitution attacks
- Share invitation replay
- Share token brute force
- Overly broad permissions
- Inconsistent authorization after revocation
- Stale cached keys
- Failure to rotate file keys when revoking users, if strong revocation is claimed
- Metadata leaks through share records
- Confused-deputy bugs between owner, sender, recipient, and viewer roles

Classify revocation claims carefully. If a recipient has already received a file key, revocation cannot make them forget it unless the file is re-encrypted under a new key.

## 8. Backend Authorization and Object Storage

Inspect the backend’s access-control model.

Evaluate:

- User ownership checks
- Recipient access checks
- Admin access boundaries
- Tenant separation, if multi-tenant
- File IDs and object keys
- Signed URLs, if used
- Upload sessions
- Download sessions
- Delete behavior
- Trash or restore behavior
- File versioning
- Folder hierarchy authorization
- Share permissions
- Rate limiting and quotas

Look for:

- Direct access to object-storage keys
- Guessable object names
- Overly permissive bucket policies
- Signed URLs with excessive lifetime
- Signed URLs not bound to method, content length, content type, or checksum
- Metadata and blob authorization checked in different systems
- Time-of-check/time-of-use bugs
- Race conditions in replacing files or revoking shares
- Broken authorization in batch APIs
- Missing authorization on thumbnails, previews, exports, or search endpoints
- Incomplete deletion from storage, database, cache, and CDN

Assume the client may be malicious and may call APIs directly.

## 9. Session, Cookie, and Token Security

Review:

- Session creation after OPAQUE login
- Session ID generation
- Refresh-token rotation
- Logout
- Session revocation
- Password-change invalidation
- MFA, if present
- Device management, if present
- Cookie flags
- CSRF protection
- CORS policy
- SameSite policy
- Token storage in browser
- JWT validation, if JWTs are used

Look for:

- Tokens stored in localStorage when cookies would be safer
- Missing HttpOnly, Secure, or SameSite flags
- Long-lived bearer tokens
- Refresh-token reuse not detected
- JWTs accepted with weak algorithms
- Missing audience, issuer, expiry, or subject validation
- Session fixation
- Session not bound to successful OPAQUE transcript
- Logout that only clears client state
- Missing invalidation after password change, account deletion, or credential reset

## 10. API Security

Inspect all APIs.

For each endpoint, identify:

- Authentication requirement
- Authorization rule
- User-controlled inputs
- Server-side validation
- Rate limits
- Side effects
- Sensitive outputs
- Error behavior
- Logging behavior

Look for:

- Mass assignment
- IDOR
- SSRF, if URLs are accepted
- Path traversal
- JSON parser differentials
- Content-type confusion
- Request smuggling risk in deployment
- Oversized request bodies
- Compression bombs
- Malicious filenames
- Unicode normalization issues
- MIME sniffing problems
- Unsafe redirects
- Cache-control mistakes
- Inconsistent validation between frontend and backend

Include a table of endpoints reviewed and suspected issues.

## 11. Metadata Privacy

Evaluate what metadata the server can see.

Specifically identify whether the following are plaintext, encrypted, authenticated, or hidden:

- Filename
- File extension
- MIME type
- File size
- Upload time
- Modified time
- Owner
- Recipient list
- Folder path
- Number of files
- Access frequency
- Sharing graph
- Thumbnail or preview data
- Search indexes

If the product claims end-to-end encryption or zero-knowledge storage, compare those claims to actual metadata exposure.

Flag any misleading claim or undocumented metadata leakage.

## 12. Frontend Security and XSS

Inspect the frontend for:

- DOM XSS
- Stored XSS through filenames, folder names, user display names, share messages, or metadata
- Reflected XSS through routes or query parameters
- Unsafe markdown or HTML rendering
- Unsafe file preview rendering
- SVG handling
- PDF preview risks
- Image metadata risks
- CSP
- Trusted Types, if applicable
- Dependency vulnerabilities
- Source-map exposure
- Error reporting leakage

Treat XSS as especially severe because it may expose passwords, OPAQUE material, derived keys, file keys, plaintext files, and decrypted metadata.

Evaluate whether the app architecture minimizes the blast radius of frontend compromise.

## 13. Supply Chain and Build Security

Review:

- Go modules
- npm dependencies
- WASM artifacts
- opaque.js source and build pipeline
- Native libraries used through CGO
- Lockfiles
- CI/CD pipeline
- Container images
- Build reproducibility
- Dependency pinning
- SRI or hash verification
- Provenance, signatures, and attestations, if any
- Secrets in CI
- Release process

Look for:

- Unpinned dependencies
- Dynamic fetching of crypto code
- WASM binary not tied to audited source
- Minified unauditable vendor code
- Deprecated cryptographic libraries
- Build-time code generation risks
- Postinstall scripts
- Excessive npm package permissions
- Leaked tokens in CI logs
- Docker images running as root
- Missing vulnerability scanning

## 14. Error Handling, Logging, and Telemetry

Inspect whether logs, metrics, traces, crash reports, and analytics include:

- Passwords
- OPAQUE messages
- OPAQUE export keys
- Argon2id salts or parameters
- Derived keys
- File keys
- Plaintext filenames
- Plaintext metadata
- Share tokens
- Authorization headers
- Cookies
- Session IDs
- Signed URLs
- Decrypted file contents
- User identifiers beyond what is necessary

Check both frontend and backend telemetry.

Flag sensitive data exposure as high severity if logs are accessible to broad internal audiences or third-party services.

## 15. Account Recovery, Password Change, and Key Rotation

If present, review:

- Password change
- Password reset
- Account recovery
- Email verification
- MFA reset
- Device enrollment
- Recovery keys
- Key rotation
- Account deletion

Evaluate:

- Whether password reset can recover encrypted files
- Whether the server ever sees file keys during recovery
- Whether recovery weakens the encryption model
- Whether changing the password rotates or rewraps appropriate keys
- Whether old sessions remain valid
- Whether old OPAQUE credentials remain usable
- Whether encrypted file keys are rewrapped safely
- Whether recovery codes are generated securely
- Whether recovery flows bypass OPAQUE guarantees

Call out any gap between user expectations and actual recoverability. For example, if files are encrypted only with a password-derived key and no recovery key exists, forgotten passwords may make files unrecoverable.

## 16. Cryptographic Design Review

Create a clear diagram or written model of the key hierarchy.

Identify:

- Password
- OPAQUE client secret or export key
- Argon2id output
- Master key
- Key-encryption key
- File key
- Chunk keys
- Metadata keys
- Share wrapping keys
- Recipient public/private keys
- Recovery keys
- Server-side secrets

For each key, document:

- Where it is generated
- Entropy source
- Where it is stored
- Whether it leaves the client
- What it encrypts or authenticates
- How it is rotated
- How it is destroyed
- What happens if it is compromised

Look for missing domain separation. Every derived key should have a clear purpose and context string, for example:

- authentication
- file-content encryption
- metadata encryption
- file-key wrapping
- sharing
- recovery
- MAC or signing
- local cache encryption

Never assume that because a primitive is strong, the composition is secure.

## 17. Testing Expectations

Evaluate the existing tests and recommend missing tests.

Look for tests covering:

- OPAQUE happy path
- OPAQUE malformed messages
- OPAQUE replay attempts
- Registration overwrite attempts
- Login with wrong password
- Login to wrong identity
- Rate limiting
- Account enumeration
- File encryption/decryption round trips
- Tampered ciphertext
- Tampered metadata
- Nonce uniqueness
- Chunk reordering
- Chunk truncation
- Wrong file key
- Wrong recipient key
- Share revocation
- Unauthorized file access
- Deleted-file access
- Batch API authorization
- XSS through filenames and display names
- Large-file handling
- Browser reload and multi-device behavior
- CGO malformed input
- Fuzz tests for parsers and native boundaries

Recommend property tests, fuzz tests, integration tests, and adversarial tests where useful.

## 18. Vulnerability Classification

For each finding, include:

- Title
- Severity: Critical, High, Medium, Low, Informational
- Confidence: High, Medium, Low
- Affected component
- Affected files or functions
- Attack preconditions
- Attack scenario
- Security impact
- Evidence from code
- Recommended fix
- Suggested tests
- Whether the issue is cryptographic, authorization-related, memory-safety-related, frontend-related, operational, or design-level

Use the following severity guidance:

### Critical

Use Critical for issues that allow:

- Remote unauthenticated compromise of user files
- Authentication bypass
- Server-wide access to plaintext files where E2EE is claimed
- OPAQUE failure enabling offline password cracking from database records
- Remote code execution
- Exfiltration of encryption keys for many users
- Signature, MAC, or encryption bypass affecting confidentiality or integrity at scale

### High

Use High for issues that allow:

- Access to another user’s encrypted or decrypted files
- Persistent XSS in a cryptographic web app
- Share authorization bypass
- File key exposure
- Account takeover under realistic conditions
- Significant metadata leakage contrary to product claims
- Replay or substitution attacks against encrypted files
- Dangerous CGO memory-safety bugs reachable by attacker input

### Medium

Use Medium for:

- Missing rate limits
- Weak but not immediately exploitable cryptographic parameter choices
- Limited IDORs
- Token lifetime issues
- Incomplete logging hygiene
- Revocation limitations not clearly disclosed
- Defense-in-depth failures

### Low / Informational

Use Low or Informational for:

- Hardening recommendations
- Minor leakage
- Documentation gaps
- Non-exploitable inconsistencies
- Code clarity issues affecting future security maintenance

## 19. Specific Questions to Answer

Answer these explicitly:

1. Does the OPAQUE implementation prevent offline password guessing if the database is stolen?
2. Is the OPAQUE server setup key protected separately from the database?
3. Is the OPAQUE export key used? If yes, how?
4. Is Argon2id being used safely and with domain separation?
5. Are Argon2id parameters attacker-controlled or downgradeable?
6. Are file encryption keys generated randomly per file?
7. Are AEAD nonces unique under each key?
8. Is ciphertext integrity verified before plaintext is used?
9. Can the server swap, replay, truncate, or roll back encrypted files without detection?
10. Are filenames and metadata encrypted, authenticated, or plaintext?
11. Can one user access another user’s files by changing IDs?
12. Can a malicious recipient access files after revocation?
13. Does sharing rely on server-controlled public keys? If so, can the server substitute keys?
14. Can XSS expose passwords, file keys, or plaintext files?
15. Are any secrets stored in localStorage, IndexedDB, logs, crash reports, or analytics?
16. Does password reset preserve encrypted data? If so, how?
17. Is the claimed security model accurately reflected in implementation and documentation?
18. Are CGO components reachable with attacker-controlled data?
19. Are WASM artifacts pinned and tied to audited source?
20. What are the top five security risks in the current design?

## 20. Output Format

Produce the review in this structure:

### Executive Summary

- Overall security posture
- Most serious risks
- Whether the system’s cryptographic claims appear justified
- Whether file confidentiality from the server is actually achieved
- Top recommended fixes

### Architecture and Data Flow Summary

Describe:

- Registration flow
- Login flow
- File upload flow
- File download flow
- Sharing flow
- Password change or recovery flow
- Key hierarchy

### Threat Model Assessment

State whether the implementation matches the expected threat model. Identify gaps.

### Findings

For each finding:

#### Finding N: [Title]

- Severity:
- Confidence:
- Component:
- Affected files/functions:
- Description:
- Evidence:
- Attack scenario:
- Impact:
- Recommendation:
- Suggested tests:

### Endpoint Review Table

Include columns:

- Endpoint
- Auth required
- Authorization rule
- Sensitive inputs
- Sensitive outputs
- Issues found
- Recommended tests

### Cryptographic Review Table

Include columns:

- Operation
- Primitive
- Key source
- Nonce/IV handling
- Associated data
- Storage location
- Issues

### Key Hierarchy

List each key and its lifecycle.

### Metadata Exposure Matrix

Include columns:

- Metadata item
- Visible to server?
- Encrypted?
- Authenticated?
- Notes

### Testing Gaps

List missing tests and prioritize them.

### Hardening Recommendations

Include practical improvements that may not be vulnerabilities.

### Open Questions

List any assumptions or missing information that blocks a definitive conclusion.

## 21. Review Style

Be direct and skeptical. If something is unclear, say so.

Do not assume cryptographic correctness because a known library is used. Verify the integration.

Do not assume client-side checks are security controls.

Do not recommend inventing new cryptographic protocols. Prefer standard, reviewed constructions and libraries.

When suggesting fixes, be concrete and implementation-oriented.

Focus especially on bugs that could expose plaintext files, file keys, passwords, OPAQUE secrets, or unauthorized shared data.

## 22. Addendum: Additional Client Surfaces and Mandatory TOTP Coverage

This addendum extends the review scope to reflect two facts about Arkfile that were not made explicit in earlier sections: (1) Arkfile ships two Go CLI clients that are first-class end-user / privileged-user surfaces alongside the browser, and (2) TOTP is mandatory 2FA for all authenticated access and user actions, enforced by a dedicated middleware that blocks every protected route until TOTP completion.

### 22.1 Go CLI Clients as First-Class Auditable Surfaces

`arkfile-client` (`cmd/arkfile-client/`) is an end-user CLI that performs the full lifecycle:

- OPAQUE registration (`/api/opaque/register/...`)
- OPAQUE login (`/api/opaque/login/...`)
- TOTP verify
- Argon2id account-key derivation via `crypto.DeriveAccountPasswordKey`
- Session persistence to disk
- A local key-agent daemon (`cmd/arkfile-client/agent.go`) that caches the derived account KEK in process memory for a configurable TTL and serves it over a Unix socket
- File encryption / chunked upload, chunked download / decryption
- Share creation and anonymous-recipient share access

`arkfile-admin` (`cmd/arkfile-admin/`) is a privileged CLI that performs:

- Admin bootstrap (single-use token, the very first admin's registration path)
- Admin OPAQUE login
- Admin TOTP
- All admin storage / billing / task-runner actions

Both CLIs:

- Are CGO-linked to libopaque / liboprf / libsodium.
- Share `auth/opaque_client.go`, `auth/opaque_multi_step.go`, `crypto/key_derivation.go`, and the OPAQUE CGO wrapper with the server.
- Are end-user-facing binaries that ship as part of Arkfile's release artifacts. They are not developer-only tools.

Review must explicitly cover:

- OPAQUE protocol-state correctness parity between CLI and browser. Any divergence in how `ClientCreateRegistrationRequest` / `ClientCreateCredentialRequest` / `ClientRecoverCredentials` / finalize are invoked.
- Password lifecycle: when is the password byte buffer zeroed? Are there code paths (such as the deliberate `// NOTE: Do NOT zero password here` in `commands.go`) where the password remains in memory longer than strictly necessary, and is that justified?
- Session file location, permissions (expect 0600), serialization of refresh token and JWT, and whether session files leak any cryptographic material (e.g. cached account KEK, OPAQUE export).
- CLI flag-based leakage surfaces:
  - `--totp-secret` — passing the TOTP shared secret on the command line exposes it via `/proc/<pid>/cmdline`, shell history, and process accounting. This defeats 2FA when the secret is durable. Treat as Medium or higher unless mitigated (e.g. immediate argv scrub, env-var-only).
  - `--password-stdin` — pipe-mode password ingress; review pipe lifetime, leftover bytes, and timeout safety.
  - `--account-key-file` — path-derived key ingestion; check file-mode requirement and any TOCTOU.
- The `arkfile-client` agent daemon:
  - Unix-socket path predictability and parent-directory mode.
  - Socket file mode (expect 0600 with owner-only access).
  - Authentication of the agent client (peer-cred check or shared cookie).
  - Lifetime of the cached account KEK (configurable TTL); behavior under `SIGTERM`, `SIGKILL`, OOM, and core-dump.
  - Memory hygiene: use of `mlock`/`munlock`, `madvise(MADV_DONTDUMP)`, or equivalent; explicit `clearBytes`/`crypto/subtle.ConstantTimeCompare` use.
  - Session-mismatch wipe logic: under what conditions is the cache wiped, and is the trigger safe against forgery?
  - Digest-cache integrity: can a malicious or compromised client poison the dedup digest cache to coerce upload/download of the wrong content?
- CLI binary supply chain (Slice F):
  - Static vs dynamic linking of libsodium / libopaque / liboprf.
  - RPATH / RUNPATH leakage, stripped symbols.
  - Reproducible builds (`-buildid=`, `-trimpath`, `CGO_LDFLAGS` reproducibility).
  - Release-artifact signing and provenance.

Findings against the CLIs follow the same severity rubric as backend findings (§18). A CGO memory-safety bug reachable through `arkfile-client` argv or stdin is High by default; a leak of the account KEK from agent memory is Critical if reachable.

### 22.2 TOTP as Mandatory 2FA (Two-Tier JWT Model)

**Policy:** TOTP is required for all authenticated access and user actions in Arkfile, in both browser and CLI clients, for regular users and admins. There is no path to authenticated state (file list, upload, download, share, admin actions, etc.) without TOTP, except documented bootstrap and dev/test flows that must themselves be reviewed.

**Enforcement model (must be verified by the audit):** Arkfile uses a two-tier JWT enforcement model:

- **Tier 1 — Post-OPAQUE Temp Token.** Issued by `/api/opaque/login/finalize` after a successful OPAQUE handshake. This token authenticates "the user proved the password" but does NOT grant access to any user action. It is accepted only by the TOTP-verify endpoint(s) and any TOTP-enrollment-completion endpoint where applicable. It must:
  - Be cryptographically distinct from the full JWT — either via separate audience claim, separate signing key, an in-DB allowlist, or a dedicated claim such as `totp_verified=false` / `purpose=totp_challenge`.
  - Have a short TTL (minutes, not hours).
  - Not be refreshable into a full JWT without TOTP completion.
- **Tier 2 — Full JWT.** Issued by the TOTP-verify endpoint after the user submits a valid TOTP code (or a valid, unused backup code). This token is the only one accepted by the TOTP middleware that gates every protected route.

**TOTP middleware chokepoint — required audit checklist:**

- Identify the exact middleware function and route registrations.
- Verify a single chokepoint exists — not scattered per-handler checks.
- Verify every protected route is wired through it (no bypass in `handlers/route_config.go`).
- Verify the middleware rejects tokens missing the "TOTP completed" claim, with constant-time comparison and a generic error response that does not differentiate "no token" / "expired token" / "missing TOTP claim" in a way that helps an attacker.
- Verify the temp token cannot be substituted for a full JWT (separate audience/signing/allowlist as above; reject in middleware).
- Verify the dev/test API surface (`ADMIN_DEV_TEST_API_ENABLED=true`) cannot disable the middleware in production builds.

**TOTP enrollment — required audit checklist:**

- Secret entropy from CSPRNG, at least 160 bits per RFC 6238 §4.
- Server-side at-rest encryption of the TOTP secret (with which key? where is that key? rotated how?).
- URI/QR generation does not leak the secret to logs, telemetry, or browser history.
- Enrollment is finalized only after the user submits a valid code (proof-of-possession), preventing accidentally-enabled but unconfigured TOTP.
- Idempotency: re-enrollment overwrites or rejects safely; no race between two concurrent enrollments.
- TOTP marked-active flag and "TOTP required" flag are server-controlled, never client-controlled.

**TOTP verify — required audit checklist:**

- Time-step = 30 s (RFC default) unless documented otherwise.
- Allowed skew window narrow (ideally ±1 step). Wider windows must be justified.
- Constant-time code comparison (e.g. `crypto/subtle.ConstantTimeCompare`).
- One-time use per step per user: a successfully-used code in step N cannot be replayed within the same step.
- Rate limit on the TOTP-verify endpoint, keyed by user (and EntityID for unauthenticated brute force at the network layer).
- Lockout after N failures within a time window. Lockout state must not enable account enumeration.

**Backup codes — required audit checklist:**

- Generation entropy and count.
- Server-side storage hashed (Argon2id or comparable) and/or at-rest encrypted. Never plaintext.
- Atomic mark-as-used (no race that allows double-spend).
- Rate-limited and lockout-eligible the same way as TOTP codes.
- Regeneration flow requires current authenticated session with TOTP completion; old codes are invalidated.
- Disclosure to the user happens exactly once at generation/regeneration, with clear UX warnings.

**Loss-of-device recovery:**

- Document the supported recovery path (backup codes only? admin reset? both?).
- If admin reset exists, audit its authorization, audit trail, and whether it weakens the TOTP guarantee.
- If forgotten password + lost device means lost account, that must be documented and consistent with Arkfile's "lost password = lost files" posture.

**CLI TOTP entry:**

- `--totp-code` (recommended): single-use, expires within the time step. Argv exposure of a one-shot code is acceptable.
- `--totp-secret` (script convenience): the durable shared secret on the command line. Flag this as at minimum Medium unless mitigated. Recommend a `--totp-secret-env` or stdin-based alternative.

**Admin TOTP:**

- Admin login forces TOTP — verify there is no admin path that bypasses TOTP.
- Admin bootstrap creates the first admin and must either (a) require immediate TOTP enrollment before any privileged action, or (b) clearly document the deferral window and constrain what the un-enrolled admin can do.

**Dev/test bypass:**

- `ADMIN_DEV_TEST_API_ENABLED=true`, `dev-reset.sh`, and any debug-mode toggles must not silently disable the TOTP middleware in non-dev builds.
- Configuration loading (`config/security_config.go`) must fail closed if conflicting flags are set in production mode.

### 22.3 Slice Mapping

- CLI auth flows, agent daemon, TOTP enrollment/verify/backup-codes/lockout/recovery, two-tier JWT enforcement -> **Slice A** (primary).
- CLI binary build/static-linking/supply-chain/signing -> **Slice F**.
- TOTP-gated route coverage at the API surface -> **Slice E**, whose Endpoint Review Table must include a "TOTP-gated?" column to formally verify the chokepoint route-by-route.
- Browser-side TOTP enroll/verify UI and storage (no TOTP secret persistence client-side beyond the QR/setup screen) -> **Slice A** (with cross-ref into Slice F for XSS impact).

