# Slice B — Crypto & Key Hierarchy

Status: **Complete** (2026-05-11). This is the consolidated, definitive deliverable for Slice B of the Arkfile in-depth security review per `docs/wip/idsrp.md`. It covers Argon2id key derivation, AES-256-GCM operations, the FEK/KEK envelope format, share-envelope crypto, metadata encryption, and the padding policy. The vendored Go stdlib `crypto/aes`, `crypto/cipher`, `golang.org/x/crypto/argon2`, `golang.org/x/crypto/hkdf`, and the TS `@noble/hashes` are treated as trusted upstreams per the plan; only call-site usage is audited.

Findings are numbered `B-01` through `B-27`, severity-ordered, single series.

---

## 0. Scope

### `idsrp.md` sections covered

- **§5** (Argon2id and KDF review) — full coverage.
- **§6** (file encryption) — primitive-level only. Streaming-wire-path, chunk-reorder protection at the HTTP layer, and S3 routing are deferred to Slice C, but the crypto-side observation that no AAD is bound to file chunks IS in scope here.
- **§11** (metadata privacy) — partial. The crypto question "is metadata encrypted/authenticated?" is in scope. The full server-visible metadata exposure matrix is finalized in Slice G with input from Slices C/D.
- **§16** (cryptographic design / key hierarchy) — full coverage, including the canonical Key Hierarchy table.
- **§17** (testing) — limited to the crypto test surface (`crypto/*_test.go`, `utils/padding_test.go`, TS `__tests__/{primitives,file-encryption,share-crypto,aes-gcm}.test.ts`).

### Files actually read

| File | LOC | Purpose |
|---|---:|---|
| `crypto/argon2id-params.json` | 7 | Argon2id parameter source-of-truth (m=65536 KiB, t=3, p=1, dk=32). |
| `crypto/chunking-params.json` | 16 | Chunking/envelope parameter source-of-truth. |
| `crypto/password-requirements.json` | 8 | Password policy source-of-truth. |
| `crypto/key_derivation.go` | 175 | `DeriveArgon2IDKey`, `GenerateUserKeySalt`, `Derive{Account,Custom}PasswordKey`, HKDF. |
| `crypto/gcm.go` | 220 | `EncryptGCM`/`DecryptGCM` and `*WithAAD` variants. |
| `crypto/envelope.go` | 22 | Comment-only file; the real format is in `file_operations.go`. |
| `crypto/file_operations.go` | 541 | `CreateEnvelope`/`ParseEnvelope`, `EncryptFEK`/`DecryptFEK`, `EncryptFile`/`DecryptFile`, `DecryptFileMetadata`. |
| `crypto/chunking_constants.go` | 111 | Embedded chunking-params loader. |
| `crypto/key_manager.go` | 279 | System-key wrap/unwrap via `ARKFILE_MASTER_KEY` + HKDF + AES-GCM. |
| `crypto/session.go` | 105 | OPAQUE-export-key-based session-key derivation — **DEAD CODE**, no callers. |
| `crypto/share_kdf.go` | 165 | `DeriveShareKey`, `CreateAAD`, share-envelope JSON helpers. |
| `crypto/password_validation.go` | 246 | Server-side password policy validator. |
| `crypto/utils.go` | 53 | `GenerateRandomBytes`, `SecureClear`, `SecureCompare`, base64 helpers. |
| `crypto/opaque_validation.go` | 1 | Empty stub. Same Greenfield concern noted in Slice A — no new finding here. |
| `crypto/gcm_test.go` | 389 | GCM round-trip, AAD, tamper, key-size tests. |
| `crypto/key_derivation_test.go` | 492 | Argon2id, salt, HKDF, ambiguous-concat tests. |
| `crypto/share_kdf_test.go` | ~535 | Share KDF tests (read header + sampled). |
| `crypto/file_operations_test.go` | — | Envelope/FEK round-trip tests (sampled). |
| `utils/padding.go` | 68 | Server-side padding policy: 2% block + ≤10% jitter, 64 KiB floor. |
| `client/static/js/src/crypto/primitives.ts` | 576 | `deriveKeyArgon2id`, `encryptAESGCM`/`decryptAESGCM`, `deriveKeyHKDF`, `constantTimeEqual`, `secureWipe`. |
| `client/static/js/src/crypto/constants.ts` | 281 | Runtime-fetched `getArgon2Params()` and `getChunkingParams()` from server APIs. |
| `client/static/js/src/crypto/file-encryption.ts` | 260 | `deriveSaltFromUsername`, `deriveFileEncryptionKey{,WithCache}`. |
| `client/static/js/src/crypto/account-key-cache.ts` | 753 | sessionStorage-backed AES-wrapped Account Key cache w/ HMAC integrity, session binding, inactivity auto-lock. |
| `client/static/js/src/crypto/aes-gcm.ts` | 155 | `AESGCMDecryptor` for chunked downloads — **no AAD parameter**. |
| `client/static/js/src/crypto/metadata-helpers.ts` | 176 | `decryptFEK`, `decryptMetadataField`, `getAccountKey`. |
| `client/static/js/src/crypto/password-validation.ts` | 297 | Client-side password policy validator, fetches from `/api/config/password-requirements`. |
| `client/static/js/src/crypto/errors.ts` | 518 | Error classes; user-friendly message map. |
| `client/static/js/src/crypto/types.ts` | 554 | TS types (one duplicate-declared interface noted). |
| `client/static/js/src/shares/share-crypto.ts` | 417 | Share envelope encrypt/decrypt; uses AAD = `shareId + fileId` string concat. |
| `cmd/arkfile-client/crypto_utils.go` | — | CLI re-implements FEK envelope using raw `crypto.EncryptGCM`/`DecryptGCM` (no AAD). |
| `handlers/uploads.go` (padding usage only) | — | Server-side padding application path. |

### Files referenced but not deep-read

- `cmd/arkfile-client/commands.go`, `cmd/arkfile-client/offline_decrypt.go`, `cmd/arkfile-client/dedup.go` — confirmed they call `DeriveAccountPasswordKey`, `DeriveCustomPasswordKey`, `DeriveShareKey`, `EncryptGCM`, `DecryptGCM` directly. Deeper CLI auth-flow audit is Slice A (done).

### Out of scope (deferred to other slices)

- OPAQUE protocol / OPAQUE export-key handling — Slice A (done).
- HTTP wire path for upload/download, streaming hash verification at network layer, IDOR on file IDs, S3 object-name predictability, signed-URL hygiene — Slice C.
- Share-handler authorization, share-ID enumeration / rate limiting, anonymous-recipient IP hygiene — Slice D.
- Logging hygiene around crypto errors (debug-mode hex dumps of nonces/ciphertext) — Slice E (cross-ref from B-12).
- WASM artifact pinning / SRI for `@noble/hashes` (which ships pure JS argon2id, not WASM) and any Argon2 WASM modules — Slice F (cross-ref from B-04).

---

## 1. Architecture & Data-Flow Summary

### 1.1 Password contexts and salts

Arkfile uses **four password contexts**, all separated cryptographically:

| Context | Where | Salt construction | Argon2id params | Output |
|---|---|---|---|---|
| OPAQUE login password | OPAQUE protocol | n/a — OPAQUE has its own internal OPRF | not Argon2id | OPAQUE export key + session keys (Slice A) |
| Account-file-encryption password (same as login pwd) | `DeriveAccountPasswordKey` | `SHA-256("arkfile-account-key-salt:" + username)` — deterministic | m=65536 KiB, t=3, p=1, dk=32 | Account-KEK (32 B) |
| Custom-file-encryption password | `DeriveCustomPasswordKey` | `SHA-256("arkfile-custom-key-salt:" + username)` — deterministic | m=65536 KiB, t=3, p=1, dk=32 | Custom-KEK (32 B) |
| Share password | `DeriveShareKey` | Random 32 B per share, base64-stored | m=65536 KiB, t=3, p=1, dk=32 | Share-KEK (32 B) |

Domain separation between the three Argon2id contexts is achieved via salt input prefixes. The OPAQUE password path is fully separated by being a different protocol (OPAQUE does its own OPRF + KDF; nothing from OPAQUE feeds into the Argon2id paths, and nothing from the Argon2id paths feeds into OPAQUE). This separation is **enforced by code structure** — `DeriveAccountPasswordKey` only ever receives the password bytes and the username; it never receives any OPAQUE intermediate.

The login password and the account-file-encryption password are **the same string the user types**, processed by two independent functions. The user types once; the client sends one copy down the OPAQUE path and one copy down the Argon2id path.

### 1.2 File encryption flow (web client)

```
plaintext file (e.g. 1.5 GB)
  └─ split into 16 MiB plaintext chunks (chunking-params.json plaintextChunkSizeBytes = 16777216)
  └─ per file: generate random FEK (32 B from crypto.getRandomValues / crypto/rand)
  └─ for each chunk i:
        nonce_i = 12 random bytes (Web Crypto generateIV() / Go gcm.NonceSize random fill)
        ct_i, tag_i = AES-256-GCM(key=FEK, iv=nonce_i, aad=NONE, pt=chunk_i)
        upload_blob_i = nonce_i || ct_i || tag_i
  └─ FEK is then wrapped:
        KEK = Argon2id(account_pwd OR custom_pwd, salt=GenerateUserKeySalt(username, "account"|"custom"))
        encrypted_FEK = [0x01][0x01 or 0x02][12-B random nonce][AES-GCM(FEK, key=KEK, aad=NONE)]
  └─ metadata encryption (filename, sha256hex):
        metadataKey = Argon2id(account_pwd, salt=GenerateUserKeySalt(username, "account"))
        for each metadata field f:
            nonce_f = 12 random bytes
            ct_f, tag_f = AES-256-GCM(key=metadataKey, iv=nonce_f, aad=NONE, pt=utf8(f))
        server stores nonce_f and (ct_f || tag_f) in separate DB columns
```

**Note 1 — `metadataKey == Account-KEK`.** Filename and SHA-256 metadata are encrypted with the same Argon2id-derived key that wraps account-context FEKs. There is no separate metadata-key derivation. This is a domain-separation omission: see B-09.

**Note 2 — no AAD anywhere on the file/metadata/FEK path.** The only AAD use in the entire Arkfile codebase is in `share-crypto.ts` for the share envelope. See B-02 / B-08.

**Note 3 — server-side padding.** After all chunks are encrypted client-side and uploaded, the server computes a target padded size from the unpadded total and appends random bytes to the last chunk. The server learns the unpadded ciphertext size before applying padding, so client-to-server confidentiality of file size is structurally absent. See B-13.

### 1.3 Share envelope flow

```
share creation (web or CLI):
  share_salt = 32 random bytes (per share)
  download_token = 32 random bytes
  download_token_hash = SHA-256(download_token)   -- stored server-side
  share_KEK = Argon2id(share_pwd, salt=share_salt, m/t/p from /api/config/argon2)
  envelope_plaintext = JSON({fek, download_token, filename?, size_bytes?, sha256?})
  aad = utf8(share_id || file_id)                  -- string concat, NO delimiter (see B-15)
  ct, tag = AES-256-GCM(key=share_KEK, iv=12-rand, aad=aad, pt=envelope_plaintext)
  server stores: share_id, file_id, share_salt, ct||tag, download_token_hash, owner_username

share access (anonymous recipient):
  client fetches by share_id -> server returns {share_salt, encrypted_envelope (ct||tag||nonce arrangement), file_id}
  share_KEK = Argon2id(share_pwd_typed_by_recipient, salt=share_salt, m/t/p from /api/config/argon2)
  aad = utf8(share_id || file_id)
  plaintext = AES-256-GCM-Open(key=share_KEK, iv, ct, tag, aad)
  parse JSON -> get fek, download_token, filename, size_bytes, sha256
  use download_token to authorize fetch of encrypted file chunks
  decrypt chunks with FEK (no AAD)
```

The share path is the only Arkfile crypto operation with AAD binding. The AAD construction (`share_id || file_id` with no delimiter) is a known theoretical concern when either field is variable-length and they share an alphabet (see B-15), but in practice both IDs are fixed-length opaque tokens, so collision is not currently exploitable. The recommendation is to use a delimiter or length prefix for hardening.

### 1.4 System key envelope

`crypto/key_manager.go` provides an envelope encryption layer for server-side system keys (JWT signing key, TOTP master key, OPAQUE server setup key, etc.). All system keys are stored encrypted in the `system_keys` table; the wrapping key is `HKDF-Expand(ARKFILE_MASTER_KEY, info="ARKFILE_<type>_KEY_ENCRYPTION")`. The master key itself lives only in the `ARKFILE_MASTER_KEY` env var.

This is structurally sound. Concerns about the env-var-only master key, the use of `REPLACE INTO`, and the `info` substring uniqueness are listed in B-16 / B-25.

### 1.5 Mobile / 6 GB-on-3 GB-RAM constraint

The 16 MiB plaintext chunk size means a streaming encrypt/decrypt loop holds at most one plaintext chunk + one ciphertext chunk + a few constants in memory simultaneously, which fits trivially on a 3 GB mobile device. The Web Crypto `encrypt`/`decrypt` calls for each chunk are bounded by that 16 MiB ceiling. **This is correctly designed.**

The 5 GB client-side `LIMITS.MAX_FILE_SIZE` cap conflicts with the AGENTS.md constraint "6 GB on 3 GB RAM". See B-27.

---

## 2. Findings

Severity-ordered. Every finding cites file:line. Confidence per finding: High = code path read and reproduced; Medium = static reasoning, plausible; Low = suggestive only.

### Finding B-01: Argon2id parameters are server-controlled (parameter downgrade) — CLIENT TRUSTS `/api/config/argon2`

- Severity: **High**
- Confidence: High
- Category: cryptographic
- Component: TypeScript crypto config layer
- Affected files / functions:
  - `client/static/js/src/crypto/constants.ts:35-72` (`loadArgon2Config`, `getArgon2Params`)
  - `client/static/js/src/crypto/primitives.ts:175-203` (`validateArgon2Params`)
  - `client/static/js/src/crypto/file-encryption.ts:120-127` (`deriveFileEncryptionKey` consumes server params)
  - `client/static/js/src/shares/share-crypto.ts:176-183, 301-308` (share-envelope encrypt/decrypt consumes server params)

**Description.** Every Argon2id derivation in the TS client — account-KEK, custom-KEK, share-KEK, metadata key — calls `getArgon2Params()`, which fetches `/api/config/argon2` over HTTPS and returns whatever JSON the server replied with. A malicious or compromised server can return `{"memoryCostKiB":1024,"timeCost":1,"parallelism":1,"keyLength":32,"variant":2}` and the client will accept it: `validateArgon2Params` only enforces `memoryCost >= 1024 KiB` (1 MiB) and `timeCost >= 1`. At those parameters the per-guess cost is roughly six orders of magnitude lower than the embedded JSON's `m=65536, t=3` and password cracking becomes feasible on commodity hardware.

**Evidence.**

```
// constants.ts:41-50
const response = await fetch('/api/config/argon2');
if (!response.ok) { throw new Error(`Failed to load Argon2 config: ${response.statusText}`); }
const config: Argon2Config = await response.json();
cachedArgon2Config = config;
```

```
// primitives.ts:175-203 -- the entire validation function
function validateArgon2Params(params: Argon2Params): void {
  if (params.memoryCost < 1024) { throw ...; }
  if (params.timeCost < 1) { throw ...; }
  if (params.parallelism < 1) { throw ...; }
  if (params.keyLength < 16 || params.keyLength > 64) { throw ...; }
}
```

There is no signature, no embedded floor that mirrors the server's `argon2id-params.json`, no upper-bound sanity ("if memoryCost is way below what we expect, abort"). The Go server-side `loadArgon2Params` does correctly load from the embedded `crypto/argon2id-params.json` and panic on parse failure (`crypto/key_derivation.go:67-76`), so the **server's own** copy is tamper-resistant after build. The problem is purely on the client side.

**Attack scenario.** A user registers and uploads a file. Months later the server is compromised. The attacker:
1. Captures the encrypted FEK and encrypted file chunks from object storage.
2. Captures the user's username (visible in DB).
3. Changes `/api/config/argon2` to return weak params.
4. Either waits for the user to log in (and observes the next-derived KEK is encrypting/decrypting with weak parameters — useful for future operations) or — more importantly — uses the weak params to do **offline cracking of the already-stored ciphertexts**. The salt is `SHA-256("arkfile-account-key-salt:" + username)`, fully derivable from the username, so offline cracking under weak Argon2id costs is straightforward.

The "offline cracking with downgraded params" attack works **even if the user never logs in again**, because the attacker chooses the params used for cracking — the stored ciphertexts were encrypted with strong params, but the attacker is free to try guesses with whichever Argon2id config they like. This means the parameter-downgrade attack is really about **what the legitimate client trusts going forward**, not about the original ciphertexts. The narrower (and still serious) framing:

- A compromised server can serve weak params to all future password derivations, so any **new** uploads, new shares, and new metadata writes from that point onward are encrypted under a trivially-crackable KEK. The user has no way to detect this.

**Impact.** Future file encryptions and re-keying flows can be silently weakened to the point of trivial offline brute force. Combined with the deterministic salt, an attacker who gets DB access can crack the user's password almost instantly. This is "loss of confidentiality from server compromise" at scale.

**Recommendation.**

1. Hard-code a **minimum floor** in `validateArgon2Params` that matches the production config: at least `memoryCost >= 65536` (64 MiB), `timeCost >= 3`. Below floor → throw, never derive.
2. Better: bake `argon2id-params.json` directly into the TS bundle at build time (the way the Go server embeds it), and refuse to use values returned from the API. The server-side endpoint becomes purely informational / diagnostic.
3. If the params truly must be runtime-configurable (e.g. for hardware tuning), require the server to sign the params blob with a key the client pinned at install time.
4. Same fix applies to chunking params (see B-03) and password requirements (see B-19).

**Suggested tests.**

- Mock `/api/config/argon2` to return `{memoryCost:1024,timeCost:1,...}`. Assert client refuses to derive a key or throws.
- Mock the endpoint to return `{memoryCost:65536,timeCost:3,...}`. Assert derivation proceeds and output matches the embedded Go derivation byte-for-byte for the same password+username.

**Cross-refs.** B-03 (chunking params downgrade), B-19 (password requirements downgrade), Slice F (WASM/JS bundle integrity).

---

### Finding B-02: File chunks have no AAD — server can swap entire files between user's own files undetected

- Severity: **High**
- Confidence: High
- Category: cryptographic
- Component: file encryption (TS client + Go server + CLI)
- Affected files / functions:
  - `client/static/js/src/crypto/aes-gcm.ts:74-101` (`AESGCMDecryptor.decryptChunk`)
  - `client/static/js/src/files/upload.ts` (encrypt-chunk loop calling `encryptAESGCM` without `aad`)
  - `crypto/gcm.go:13-39` (`EncryptGCM` has no AAD parameter)
  - `crypto/file_operations.go:403-455` (`EncryptFile`/`DecryptFile` route through `EncryptGCM`/`DecryptGCM`)
  - `cmd/arkfile-client/crypto_utils.go` (CLI uses `crypto.EncryptGCM` without AAD)

**Description.** File chunks are encrypted with AES-256-GCM where the AAD is **always empty**. No chunk-index binding, no file-ID binding, no per-file salt mixed into the ciphertext. The encrypted blob carries only `[nonce][ct][tag]`. The decryption function `decryptChunk` accepts whatever `encryptedChunk: Uint8Array` it is given and decrypts under the FEK.

**Evidence.**

```
// aes-gcm.ts:87-95
const decrypted = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: nonce, tagLength: this.tagSize * 8 },
  this.key,
  ciphertextWithTag
);
```

```
// upload.ts (chunk encryption)
const result = await encryptAESGCM({ data, key });   // no `aad`
```

```
// crypto/gcm.go:37
ciphertext := gcm.Seal(nonce, nonce, data, nil)      // AAD = nil
```

Server-side, the upload session stores `file_id`, `storage_id`, `chunk_count`, etc. in the DB. The chunks themselves are opaque blobs. The download path returns chunks by `file_id` + chunk-index, and the client decrypts them under the FEK retrieved from that file's encrypted-FEK column.

**Attack scenario.** Alice owns two account-encrypted files, F1 and F2, both encrypted with the **same account-KEK** (because she uses the same account password for both). F1's chunks have FEK1, F2's chunks have FEK2. A malicious server:

1. Returns F2's `encrypted_fek` row in response to Alice's request for F1. The envelope header byte 0x01 says "account-encrypted", which matches what F1 would have produced. The KEK is the same account-KEK. AES-GCM-decrypt succeeds. Alice's client now holds FEK2 thinking it's FEK1.
2. Returns F2's chunks in response to Alice's request for F1's chunks. Each chunk is `[nonce][ct][tag]` encrypted under FEK2. The client decrypts under FEK2 — succeeds.
3. Returns F2's encrypted metadata row in response to Alice's request for F1's metadata. The metadata is encrypted under the same `metadataKey == Account-KEK`. Decrypts successfully and returns "filename: F2.pdf, sha256: <F2's hash>".

The client now believes it downloaded F1, but actually decrypted F2 with full integrity verification successful. The SHA-256 verification at the streaming layer (`sw-streaming-download.ts`) passes because the metadata's sha256 was also swapped.

The only thing the user might notice is that the filename is wrong — but if the server is in the middle of a confused-deputy attack (e.g. wants the user to publish what they think is "vacation.jpg" but is actually "trade-secrets.pdf"), or if the user is doing a bulk download, the filename mismatch may go undetected.

**Impact.** A malicious server can substitute any file the user owns for any other file the user owns. This breaks the basic E2EE guarantee that "the user gets the file they asked for". It does NOT break confidentiality of any file (the attacker is the server and already has the ciphertext), but it breaks **file-identity authenticity** — a property the architecture appears to promise but does not deliver.

The same attack works for cross-user files only when both files share a KEK, which they don't (KEK is derived from password + username). So the attack is **per-user, intra-user file substitution**. Severity is still High because:
- Recipients of shares are protected by the share-envelope AAD (`share_id||file_id`) which IS bound. So this only affects the owner's own re-downloads. But that's still a privacy/correctness violation.
- The user has no cryptographic way to detect it.

**Recommendation.**

Bind `file_id` (and chunk index for streaming) into the AEAD AAD for every file-chunk encryption and every FEK envelope encryption. Concretely:

- For each chunk: `aad = utf8("file:" || file_id || ":chunk:" || htonl(chunk_index))`.
- For the FEK envelope: `aad = utf8("fek:" || file_id)`.
- For metadata fields: `aad = utf8("meta:" || file_id || ":" || field_name)`.

This is a backward-incompatible format change. Since Arkfile is greenfield and the plan permits format breaks, that should be fine. Bump the envelope version byte to `0x02` and reject `0x01` after migration.

Cross-language: the change must land in (a) Go server tests / reference encryption, (b) TS client `aes-gcm.ts` + `metadata-helpers.ts` + `upload.ts`, (c) Go CLI `crypto_utils.go`.

**Suggested tests.**

- Round-trip with AAD; assert decrypt without AAD fails.
- "Swap two files of the same user" test: encrypt F1 and F2 with the same Account-KEK but different FEKs, both with file_id bound into AAD. Attempt to decrypt F2's chunks under F1's `file_id` AAD; assert failure.
- Chunk reorder test: encrypt 4 chunks of one file, swap chunks 1 and 3 in the on-wire order, attempt decryption; assert that the chunk-index-bound AAD detects the swap.

**Cross-refs.** B-05 (no chunk reorder protection — same root cause). B-08 (FEK envelope has no AAD — same root cause). Slice C (the wire path will need parallel work to plumb `file_id` and chunk-index to the AEAD layer).

---

### Finding B-03: Chunking parameters are also server-controlled — server can set absurd chunk sizes

- Severity: **High**
- Confidence: High
- Category: cryptographic / resource-exhaustion
- Component: TypeScript chunking config layer
- Affected files / functions:
  - `client/static/js/src/crypto/constants.ts:179-209` (`loadChunkingConfig`, `getChunkingParams`)
  - `client/static/js/src/crypto/aes-gcm.ts:48-61` (`AESGCMDecryptor.fromRawKey` reads nonceSize/tagSize from server)
  - `client/static/js/src/files/upload.ts` (uses `plaintextChunkSizeBytes` from server)

**Description.** Exactly like B-01, but for chunking parameters. The client fetches `/api/config/chunking` to learn the plaintext chunk size, nonce size, tag size, and the envelope key-type byte values. There is **no validation** at all on the response. A malicious server can set:

- `nonceSizeBytes: 4` — disastrously short nonce, repeats almost immediately under any single key.
- `tagSizeBytes: 4` — tag-forgery probability 2^-32 instead of 2^-128.
- `plaintextChunkSizeBytes: 2147483647` — 2 GiB chunks crash low-RAM mobile clients (the AGENTS.md mobile constraint).
- `keyTypes.account: 0x02` and `keyTypes.custom: 0x01` — swap the envelope key-type values, causing the client to try the wrong KEK for FEK decryption (mostly self-DoS).

**Evidence.** No validation in `loadChunkingConfig`; the parsed JSON is cached and used verbatim.

**Attack scenario.** Compromised server returns `{aesGcm:{nonceSizeBytes:4,tagSizeBytes:4,keySizeBytes:32}, plaintextChunkSizeBytes:16777216, envelope:{...}}`. Subsequent uploads use 4-byte nonces; with random nonce generation, collisions become likely after ~2^16 chunks per FEK (birthday bound), trivially exploitable to recover plaintext via the well-known GCM nonce-reuse attack. The user has no way to know their fresh uploads are using weakened crypto.

**Impact.** Same blast radius as B-01: silent downgrade of confidentiality and integrity guarantees for any new operations after a server compromise. Also enables a memory-DoS attack against constrained clients.

**Recommendation.**

1. Hard-code chunking constants in the TS bundle (`plaintextChunkSizeBytes`, `nonceSizeBytes`, `tagSizeBytes`, `keySizeBytes`) and refuse to accept different values from the server endpoint. The `/api/config/chunking` endpoint should be retained for diagnostics / cross-check only, never as the source of truth at runtime.
2. Same hardening pattern as B-01.

**Suggested tests.**

- Mock `/api/config/chunking` to return `nonceSizeBytes: 4`. Assert client refuses.
- Mock to return mismatched values vs the embedded Go constants. Assert mismatch detection.

**Cross-refs.** B-01, B-19, Slice F supply-chain.

---

### Finding B-04: TypeScript Argon2id runs on the main thread, blocking the UI for several seconds

- Severity: **Medium**
- Confidence: High
- Category: design / availability
- Component: TypeScript crypto
- Affected files / functions:
  - `client/static/js/src/crypto/primitives.ts:121-170` (`deriveKeyArgon2id` calls `@noble/hashes` argon2id synchronously inside a Promise wrapper, no Worker)
  - `client/static/js/src/shares/share-access.ts` (acknowledges the issue in its UI message)

**Description.** `@noble/hashes/argon2.js` is a pure-JS implementation. At the embedded params (m=64 MiB, t=3), derivation takes several seconds on desktop browsers and significantly longer on mobile. The code wraps the call in `withTimeout` and a Promise, but **does not move it to a Web Worker**, so the main thread is blocked. `share-access.ts` even contains a comment explicitly describing this as a known issue:

```
// the Argon2id KDF inside `decryptShareEnvelope` runs synchronously on the
// main thread and blocks the JavaScript event loop for its entire
// ...
// The correct fix would be to move Argon2id into a Web Worker so the
// event loop stays responsive during the derivation. Until then, the ...
```

**Evidence.** The known-issue comment in `share-access.ts` + the absence of any `Worker` instantiation in `primitives.ts` or callers.

**Attack scenario.** Not a direct security attack, but it has security-relevant consequences:
- A user who waits 5–10 seconds for a key derivation may give up and rage-quit — degrading the willingness to use strong passwords / 2FA / shares.
- Combined with B-01, if the server can convince the client that Argon2id is "fast", users are more likely to tolerate weak params silently because they don't perceive the cost change.
- Mobile users on constrained CPUs may experience the page being killed by the OS during long synchronous JS execution.

**Impact.** Usability degradation that incentivizes parameter weakening. Medium severity as a defense-in-depth issue.

**Recommendation.** Move Argon2id derivation into a Web Worker. The TS test file `primitives.test.ts` already uses fast params for tests; production code should use the embedded params but in a Worker context. Pure-JS Argon2id in a Worker is straightforward; alternatively use a WASM Argon2id build (then Slice F supply-chain concerns apply to the WASM).

**Suggested tests.** Performance test that asserts main-thread responsiveness during derivation (e.g. `requestAnimationFrame` continues firing).

**Cross-refs.** B-01 (parameter strength), B-19 (password policy weakening pressure), Slice F (WASM choice if Worker-WASM is adopted).

---

### Finding B-05: Chunk reordering and truncation are not detected by the crypto layer

- Severity: **Medium**
- Confidence: High
- Category: cryptographic
- Component: file encryption
- Affected files / functions: Same as B-02; this is the same root cause framed from a different angle.

**Description.** Because chunk index is not bound into AEAD AAD (see B-02), an attacker between the client and storage backend can:

1. **Reorder** chunks: serve chunk 4 first, chunk 1 last, etc. The AES-GCM decryption of each chunk succeeds individually under the FEK. The resulting plaintext stream is corrupted/jumbled but cryptographically "authentic" per-chunk.
2. **Truncate** chunks: stop serving after chunk N of M. The client receives valid-looking plaintext for chunks 1..N but never sees N+1..M. The Service Worker streaming-download path's SHA-256 verification at the end would catch a mismatch against the metadata-stored full-file sha256 — but only after the truncated plaintext has already been streamed to disk via the browser's download manager.
3. **Duplicate** chunks: serve chunk 3 twice. Same per-chunk authenticity, but the file is now corrupted.

**Evidence.** `sw-streaming-download.ts` does hash plaintext as it streams and compares to expected at completion — but the bytes have already left the WritableStream by then. The user has them on disk regardless.

**Attack scenario.** Same shape as B-02. A malicious server can corrupt downloads in semi-plausible ways without breaking the per-chunk authenticator.

**Impact.** Integrity loss in downloads. Severity is Medium rather than High because the SHA-256 metadata check provides a probabilistic safety net (the user is warned post-facto). But the warning is a `showWarning` toast, not a download abort — the file has already landed on disk.

**Recommendation.**

1. Bind chunk index into AEAD AAD (same fix as B-02): `aad = utf8(file_id || ":" || htonl(chunk_index) || ":" || htonl(total_chunks))`. Now any reorder/truncate/duplicate fails at the AEAD layer, before plaintext is released to the consumer.
2. Strongly consider not releasing decrypted plaintext to the browser download manager until **all** chunks have been verified. The current streaming-to-disk-with-post-hoc-warning UX is dangerous because users tend to ignore warnings on already-completed downloads.

**Suggested tests.** Reorder/truncate/duplicate chunks in a Playwright e2e test; assert the download is aborted, not warned post-facto.

**Cross-refs.** B-02, Slice C (wire path), `docs/erasure-coding.md` (claims around durability).

---

### Finding B-06: Padding is server-applied — server sees the unpadded ciphertext size before padding is added

- Severity: **Medium**
- Confidence: High
- Category: privacy / design
- Component: padding policy (`utils/padding.go` + `handlers/uploads.go`)
- Affected files / functions:
  - `utils/padding.go:25-46` (`CalculatePaddedSize` — runs on server)
  - `handlers/uploads.go:` (server computes `paddedSize` from client-supplied `request.TotalSize`, then appends random padding to the last chunk after the client uploads it)

**Description.** The privacy goal of file-size padding is to hide the original size from observers — chiefly, the server. Arkfile's padding is computed and appended **by the server**, after the client has already uploaded the unpadded encrypted blob and told the server the unpadded total size in the upload-session request. This means:

- The server always knows the unpadded ciphertext size (≈ plaintext size + small AEAD overhead).
- The padded size that's persisted is bigger, but only to obfuscate the size from **someone who steals the S3 object** — not from the server.

**Evidence.**

```
// handlers/uploads.go
paddingCalculator := utils.NewPaddingCalculator()
paddedSize, err := paddingCalculator.CalculatePaddedSize(request.TotalSize)
// ... server stores paddedSize and adds random padding bytes to last chunk
```

The server logs the relationship: `"INSERT INTO upload_sessions ... padded_size ..."` keyed to `total_size`.

**Attack scenario.** A malicious server operator learns:
- Every user's exact ciphertext sizes for every uploaded file. With ~25 bytes of AES-GCM overhead per 16 MiB chunk and a 2-byte envelope header, the plaintext size is recoverable to within ~100 bytes from the unpadded ciphertext size.
- Even **after** the server is reset and the only thing left is the S3 bucket, the padded size is only ~2.2% bigger than the unpadded size for files > 3.2 MiB (because the block is 2% of size + ≤10% of 2% jitter). So an external observer with bucket-only access still learns the plaintext size to within ~2.2%.

**Impact.** The padding policy provides essentially no privacy from the server, and only weak privacy from an external bucket observer. Arkfile's `docs/AGENTS.md` claims that "the server must know nothing about the nature of the data belonging to clients" — this is undermined by server-visible exact ciphertext sizes.

**Recommendation.**

1. Move padding to the client: client pads the plaintext (or the ciphertext stream — either is fine if done before sending) to a target size from a defined size ladder, encrypts, uploads. The server never sees the unpadded length.
2. Replace the 2%-block / 10%-jitter scheme with a more privacy-protective ladder: e.g. powers of 2, or `Padmé` (https://lbarman.ch/blog/padme/). The current 2% block leaks ~5–6 bits of size information even in the best case.
3. Document the size-leak explicitly in `docs/privacy.md` so the threat model is honest about what padding does and does not protect.

**Suggested tests.** Compute the average bits-of-size-information-leaked under a variety of file-size distributions; assert it is below a threshold defined in the threat model.

**Cross-refs.** B-13 (related: metadata length leak), Slice C (the upload wire format change), Slice E (logging of `paddedSize` and `total_size`).

---

### Finding B-07: `metadataKey == Account-KEK` — same key wraps FEK *and* encrypts metadata

- Severity: **Medium**
- Confidence: High
- Category: cryptographic / design
- Component: file metadata encryption
- Affected files / functions:
  - `crypto/file_operations.go:486` (`DecryptFileMetadata`: `derivedKey := DeriveAccountPasswordKey([]byte(password), username)`)
  - `client/static/js/src/crypto/metadata-helpers.ts:165-175` (`decryptMetadataField` uses caller-supplied `account_key`)

**Description.** Filename and SHA-256 metadata are encrypted with the **same** Argon2id-derived 32-byte key that is used to wrap account-context FEKs. There is no separate derivation for the metadata-encryption key. The same key thus has two cryptographic roles:

1. **KEK** for FEK envelopes (wrapped under AES-GCM with no AAD).
2. **DEK** for file metadata fields (filename and sha256-hex, each AES-GCM with no AAD).

**Evidence.**

```
// crypto/file_operations.go:486
// Use account password derivation (default for file metadata)
derivedKey := DeriveAccountPasswordKey([]byte(password), username)
```

There is no HKDF expansion to derive a separate metadata key. The raw Argon2id output is used directly for both purposes.

**Attack scenario.** AES-256-GCM is robust under key reuse with unique nonces, so this is NOT an immediate exploitable vulnerability. However, it violates standard cryptographic hygiene (one key, one purpose):

- If a future code path accidentally reuses a metadata nonce as a FEK-wrap nonce (or vice versa), GCM nonce-reuse instantly leaks the XOR of the two plaintexts.
- If a future protocol change adds AAD to one path but not the other, AAD reuse semantics can have unexpected interactions.
- If the metadata-encryption logic ever uses a deterministic nonce (e.g. nonce = SHA-256(field_name)), and the FEK-wrap path uses a random nonce that happens to collide, same problem.

The current implementation uses random nonces everywhere, so the immediate failure mode is closed. But the lack of domain separation is fragile — a single nonce-handling bug becomes catastrophic instead of localized.

**Impact.** Currently latent — no exploit. Medium severity because the design fragility increases the blast radius of future bugs.

**Recommendation.**

1. Derive a per-purpose key via HKDF from the Account-KEK:
   - `metadata_key = HKDF-Expand(account_kek, info="arkfile-metadata-key", L=32)`
   - `fek_wrap_key = HKDF-Expand(account_kek, info="arkfile-fek-wrap-key", L=32)`
2. Use each only for its purpose. The Argon2id output never directly encrypts anything.
3. Mirror in the TS client and CLI.

**Suggested tests.** Property test: assert `metadata_key != fek_wrap_key` for any input. Assert that swapping one for the other fails decryption.

**Cross-refs.** B-02 / B-08 (no AAD increases risk of nonce-reuse interactions).

---

### Finding B-08: FEK envelope (encrypted-FEK) has no AAD — see B-02

- Severity: **Medium** (subsumed by B-02 as part of the same root issue but listed separately for clarity)
- Confidence: High
- Category: cryptographic
- Component: FEK envelope
- Affected files / functions:
  - `crypto/file_operations.go:316-353` (`EncryptFEK`: `encryptedFEK, err := EncryptGCM(fek, derivedKey)` — no AAD)
  - `client/static/js/src/crypto/metadata-helpers.ts:112-139` (`decryptFEK` calls `decryptChunk` without AAD)

**Description.** The FEK envelope is `[0x01][0x01 or 0x02][12-B nonce][AES-GCM(FEK, KEK, aad=∅)]`. The KEK is derived from `account_pwd + username` (or `custom_pwd + username`). There is no AAD binding to the file_id, the user_id, or anything else.

**Evidence.** See "EncryptFEK" in `crypto/file_operations.go:316-353`. The `EncryptGCM` call is the AAD-less variant.

**Attack scenario.** As in B-02: server can swap one of Alice's encrypted-FEK blobs for another (both encrypted under the same account-KEK), and the swap is undetected by the FEK decrypt itself. The downstream file-body decryption would also succeed because chunks have no AAD either (B-02).

**Impact.** Same as B-02; this is a sub-problem.

**Recommendation.** Bind `file_id` into AAD for FEK envelope: `aad = utf8("fek:" || file_id)`. Mirror in TS/CLI.

**Cross-refs.** B-02, B-07.

---

### Finding B-09: Embedded JS comment claims Argon2id parameters of "256MB, 8 iterations" — actual production is 64MB, 3 iterations

- Severity: **Low**
- Confidence: High
- Category: design / documentation hygiene
- Component: TypeScript file-encryption
- Affected files / functions:
  - `client/static/js/src/crypto/file-encryption.ts:45-46` ("The high memory/time cost (256MB, 8 iterations) makes brute force attacks impractical")

**Description.** Stale comment that claims wildly more expensive Argon2id parameters than the build actually uses. The embedded `argon2id-params.json` has `memoryCostKiB: 65536` (64 MiB) and `timeCost: 3`. The comment in `file-encryption.ts` claims "256MB, 8 iterations". This is a 4x overstatement of memory and a ~2.7x overstatement of time. Anyone reading the code who trusts the comment will overestimate the cracking cost.

**Evidence.** Quoted above.

**Attack scenario.** Not an attack; an honesty/transparency issue called out by `AGENTS.md` §"Honesty and Transparency".

**Impact.** Misleading developers and security reviewers about the actual cost.

**Recommendation.** Either bump the production parameters to match the comment, or fix the comment to reflect reality. Given the constraint that the TS Argon2id runs on the main thread (B-04) and bumping to 256 MiB would make it intolerably slow, the comment should be fixed first; bumping the parameter is a separate change gated on B-04.

**Cross-refs.** B-04.

---

### Finding B-10: `crypto/session.go` is dead code

- Severity: **Low**
- Confidence: High
- Category: design / hygiene
- Component: `crypto/session.go`
- Affected files / functions:
  - `crypto/session.go:1-105` — entire file
  - No callers anywhere in the project (verified by grep of all exported symbols)

**Description.** `crypto/session.go` defines `DeriveSessionKey`, `DeriveJWTSigningMaterial`, `ValidateSessionKey`, `SessionKeyInfo`, `CreateSessionKeyInfo`, and `SecureZeroSessionKey` — all built around an "OPAQUE export key" input. Slice A established that the OPAQUE export key is **not used** by Arkfile (the export key is part of the OPAQUE protocol output but Arkfile takes the OPAQUE session keys via the libopaque server-side API, not the export key on the client). The `session.go` API has no callers. The constants `SessionKeyContext`, `JWTSigningContext`, `TOTPEncryptionContext` are also unused — JWT signing material in fact comes from `KeyManager.GetOrGenerateKey("jwt_signing_key_v1", "jwt", 64)`, and TOTP encryption material comes from `KeyManager.GetOrGenerateKey("totp_master_key_v1", "totp", 64)`. None of the `crypto/session.go` constants flow into either.

**Evidence.** `grep -r "DeriveSessionKey\|DeriveJWTSigningMaterial\|SessionKeyContext\|JWTSigningContext\|TOTPEncryptionContext\|ValidateSessionKey\|SessionKeyInfo\|SecureZeroSessionKey"` returns matches only inside `crypto/session.go` itself.

**Attack scenario.** Not an attack. Greenfield concern per `AGENTS.md`: dead code is technical debt and a future-bug risk.

**Impact.** Future readers may believe these APIs are active and reason about the system as if export-key-derived session keys exist. They do not.

**Recommendation.** Delete `crypto/session.go`. If at some future point Arkfile decides to consume the OPAQUE export key, the design discussion can happen fresh, with current understanding of the threat model.

**Cross-refs.** Slice A finding on OPAQUE export key unused.

---

### Finding B-11: `crypto/opaque_validation.go` is an empty stub

- Severity: **Low**
- Confidence: High
- Category: design / hygiene
- Component: `crypto/opaque_validation.go`
- Affected files / functions: `crypto/opaque_validation.go:1` — single line `package crypto`.

**Description.** Empty stub file. Already noted in Slice A; mentioning here for crypto-package completeness.

**Recommendation.** Delete the file.

---

### Finding B-12: GCM debug-mode logging dumps nonces and tag-region hex to stdout

- Severity: **Low**
- Confidence: High
- Category: logging hygiene / privacy
- Component: `crypto/gcm.go`
- Affected files / functions: `crypto/gcm.go:67-99, 191-217`

**Description.** When `DEBUG_MODE=true`, `DecryptGCM` and `DecryptGCMWithAAD` print:

- The full 12-byte nonce in hex.
- The last 16 bytes of the ciphertext (which include the AEAD tag).
- Lengths of key/nonce/ciphertext.
- First 8 bytes of the data payload on too-short inputs.

```
fmt.Printf("GCM decrypt context: total_data=%d, nonce_size=%d, ciphertext_size=%d, nonce=%x\n", ...)
fmt.Printf("GCM decrypt failure: last_16_bytes_of_ciphertext=%x (includes tag)\n", ...)
```

**Attack scenario.** Debug mode is gated by an env var. In `dev-reset.sh` workflows it's enabled. In production it should not be, but a misconfiguration would dump per-decrypt nonce hex to stdout (and thus journald or whatever captures the server's stdout). This is not a confidentiality break — nonces are public — but logging the tag region complicates incident response: any logs shared with third parties (support, observability vendors) now contain partial cryptographic state.

**Impact.** Low. The bigger concern is the pattern: a `DEBUG_MODE=true` toggle should not leak cryptographic state into shared logs by default. AGENTS.md §"Privacy posture" says "no PII in logs" — nonces aren't PII, but the principle of minimal cryptographic exposure in logs is reasonable defense-in-depth.

**Recommendation.** Replace `fmt.Printf` with structured logging at a `trace` or `debug` level that is filtered out in any non-development build. Better: never log the tag region, only lengths. Add a build flag (or config-fail-closed in `config/security_config.go`) that hard-disables these prints in production binaries regardless of env var.

**Cross-refs.** Slice E (logging hygiene), Slice A finding on DEBUG_MODE in test-deploy.

---

### Finding B-13: `DecryptFileMetadata` hardcodes account-context for metadata decryption — no support for custom-context-encrypted metadata, but the API permits it

- Severity: **Low**
- Confidence: Medium
- Category: design / consistency
- Component: `crypto/file_operations.go:DecryptFileMetadata`
- Affected files / functions: `crypto/file_operations.go:477-509`

**Description.** `DecryptFileMetadata` takes a `password` and a `username` and always derives the metadata-decryption key via `DeriveAccountPasswordKey`. The function has no `keyType` parameter. The comment at line 485 says "Use account password derivation (default for file metadata)". But the FEK envelope carries a key-type byte that distinguishes account-wrapped (0x01) from custom-wrapped (0x02). For custom-wrapped FEKs, the user is prompted for a different password (the custom password). What happens to **metadata for custom-wrapped files**? The current code path implies metadata is always encrypted with the **account** key regardless of whether the FEK is wrapped with account or custom — meaning the user must remember **both** passwords to access a custom-wrapped file (custom to decrypt the FEK, account to decrypt the filename). This is consistent with `client/static/js/src/crypto/metadata-helpers.ts:165` which always uses `account_key`.

The design is internally consistent but the rationale ("metadata is always encrypted with account key, file body with FEK wrapped under account or custom") is not documented in this file's comments. A reader might mistakenly assume metadata respects the key-type byte and pass the wrong key.

**Evidence.** Quoted above.

**Attack scenario.** Not an attack. Documentation gap and API smell. If a future contributor adds a `keyType` parameter without realizing the established invariant, they might split the metadata key per file and forget to migrate, breaking decryption.

**Impact.** Low. Future-maintenance risk.

**Recommendation.**

1. Document the invariant clearly in `crypto/file_operations.go` near `DecryptFileMetadata` and `EncryptFEK`: "Metadata is always encrypted with the account-derived key, regardless of FEK key-type." Reference `docs/AGENTS.md` §"Password Contexts and Key Derivation".
2. Add a server-side check that prevents custom-context metadata writes (defensive — the API should refuse to accept a metadata field encrypted under a non-account key).
3. Consider adding the key-type byte to the metadata structure for future flexibility.

**Cross-refs.** B-07 (related: metadata key vs FEK-wrap key are the same key).

---

### Finding B-14: `EncryptFile` rejects empty plaintext but `EncryptGCM` accepts it — inconsistency

- Severity: **Low**
- Confidence: High
- Category: API consistency
- Component: `crypto/file_operations.go:403-419` vs `crypto/gcm.go:13-39`

**Description.** `EncryptFile(data, fek, keyType)` does `if len(data) == 0 { return nil, fmt.Errorf("cannot encrypt empty data") }`. The underlying `EncryptGCM(data, key)` happily encrypts empty data (the GCM test `TestEncryptDecryptGCM_EmptyPlaintext` proves this works). This means a user with a zero-byte file cannot use `EncryptFile`, even though there's no cryptographic reason to refuse — GCM authentication of an empty payload is well-defined.

**Evidence.** Quoted above.

**Attack scenario.** Not a security issue, a usability issue. Zero-byte file uploads will fail at the crypto layer.

**Impact.** Minor. Most apps don't care about zero-byte uploads, but the inconsistency is surprising.

**Recommendation.** Either (a) make `EncryptFile` accept empty plaintext, or (b) make `EncryptGCM` reject empty plaintext — and pick one consistent answer. Recommend (a).

Note: in practice, neither `EncryptFile` nor `DecryptFile` are called from the production server/CLI code paths — they're test/reference helpers. Real chunked uploads call `EncryptGCM` directly. So this is mostly a hygiene issue.

**Cross-refs.** B-17 (these helpers are dead in production).

---

### Finding B-15: `CreateAAD` for share envelopes concatenates `share_id || file_id` without a delimiter — theoretical AAD collision

- Severity: **Low**
- Confidence: Medium
- Category: cryptographic
- Component: `crypto/share_kdf.go:CreateAAD`, `client/static/js/src/shares/share-crypto.ts:186, 311`
- Affected files / functions:
  - `crypto/share_kdf.go:163-165` — `return []byte(shareID + fileID)`
  - `client/static/js/src/shares/share-crypto.ts:186` — `const aad = new TextEncoder().encode(shareId + fileId);`

**Description.** AAD is constructed as the byte concatenation of `shareID` and `fileID` strings with no separator. For two pairs of IDs to produce the same AAD, you would need `shareID_1 + fileID_1 == shareID_2 + fileID_2`. With fixed-length IDs (UUIDs, fixed-base64 token strings), this is not possible. With variable-length IDs over the same alphabet, it is. In Arkfile's current schema, both IDs are fixed-format opaque tokens (UUIDs or base64-encoded 32-byte values), so collision is **not currently exploitable**.

**Evidence.** Quoted above. The Go test `TestDecryptGCMWithAAD_WrongAADFails` (`crypto/gcm_test.go:299-301`) uses test inputs that already could have collided if the IDs had varying lengths: `"share-id-001file-id-abc"` vs `"share-id-002file-id-abc"` differ in the suffix of the share-id portion, not in the boundary between share_id and file_id, so the test doesn't actually probe the delimiter-less concatenation risk.

**Attack scenario.** None currently exploitable given fixed-length IDs. If a future schema change makes either ID variable-length or merges them into a single field, a malicious server could craft `share_id_A` and `file_id_A` that produce the same AAD as `share_id_B` and `file_id_B`, enabling envelope substitution.

**Impact.** Low; depends on future schema changes. Hardening recommendation.

**Recommendation.** Use a delimiter or length-prefix construction:
- Simplest: `aad = utf8(shareID + "|" + fileID)` (and verify both inputs forbid the delimiter character).
- Better: length-prefixed: `aad = htonl(len(shareID)) || shareID || htonl(len(fileID)) || fileID`.

Apply identically in Go (`crypto.CreateAAD`) and TS (`share-crypto.ts`).

**Suggested tests.** Add a test that uses two ID pairs designed to collide under naive concatenation and asserts they produce different AADs.

**Cross-refs.** Slice D (share-handler authz + envelope storage).

---

### Finding B-16: Single `ARKFILE_MASTER_KEY` env-var-only master key — operator hardening gap

- Severity: **Low**
- Confidence: High
- Category: operational / key-management
- Component: `crypto/key_manager.go:31-66`

**Description.** All server-side system keys (JWT signing, TOTP master, OPAQUE server setup, etc.) are wrapped under HKDF-derived subkeys of a single 32-byte master key sourced from the `ARKFILE_MASTER_KEY` env var. The env var lives in `/opt/arkfile/etc/secrets.env` (per AGENTS.md / `.clinerules` — I have not read that file). If an attacker reads that env var (process listing, debugger, memory inspection, core dump), they can decrypt every system key.

**Evidence.**

```
masterKeyHex := os.Getenv("ARKFILE_MASTER_KEY")
masterKey, decodeErr := hex.DecodeString(masterKeyHex)
```

No key-rotation mechanism, no KMS/HSM integration, no encrypted-rest-on-disk-with-separate-passphrase pattern. The master key is in plaintext memory for the entire process lifetime.

**Attack scenario.** Server compromise that yields memory access (e.g. via `gdb attach`, `/proc/<pid>/mem`, or a memory-corruption RCE) immediately exposes the master key. From the master key + DB dump, the attacker recovers every system key.

**Impact.** Low in isolation (this is standard for env-var-secrets-on-disk patterns). The reason it's even Low rather than Informational is that AGENTS.md and the threat model in `idsrp.md` §2 explicitly include "malicious or compromised server operator" as an adversary — and against that adversary, the env-var pattern is a blanket failure. There's no realistic mitigation without KMS/HSM.

**Recommendation.**

1. Document explicitly that the operator threat is not addressed by the current key-management design.
2. Hardening (future): support pluggable master-key sources (HashiCorp Vault, AWS KMS, etc.). The current design is fine for a single-tenant self-hosted scenario but not for the "compromised server operator" adversary listed in the threat model.
3. Minor: add `mlock(2)` and `MADV_DONTDUMP` to the master-key buffer to keep it out of core dumps and swap. (Go's `mlock` story is awkward but feasible via syscall.)

**Cross-refs.** Slice F (systemd hardening — `ProtectSystem`, `MemoryDenyWriteExecute`, `LockPersonality`).

---

### Finding B-17: `EncryptFile`/`DecryptFile`/`EncryptFEK`/`DecryptFEK` are unused outside tests — confusing dead-ish surface

- Severity: **Low**
- Confidence: High
- Category: design / hygiene
- Component: `crypto/file_operations.go:316-455`

**Description.** Grep across `/cmd`, `/handlers`, `/auth`, etc. shows zero callers of `crypto.EncryptFile`, `crypto.DecryptFile`, `crypto.EncryptFEK`, `crypto.DecryptFEK` outside `crypto/file_operations_test.go`. The production server uses chunked operations directly. The CLI re-implements the FEK envelope in `cmd/arkfile-client/crypto_utils.go` using raw `EncryptGCM`/`DecryptGCM`. So the `EncryptFEK` Go function is reference code that doesn't match what the CLI actually does.

**Evidence.** `grep -r "EncryptFEK\(|DecryptFEK\(|EncryptFile\(|DecryptFile\(" --include="*.go"` shows only definitions and test callers.

**Attack scenario.** Not an attack. Future contributor risk: someone modifies `crypto.EncryptFEK` thinking it's the canonical path, doesn't update the CLI's parallel implementation, and the two diverge silently.

**Impact.** Low. Maintenance risk.

**Recommendation.**

1. Either consolidate the CLI's FEK envelope implementation onto the shared `crypto.EncryptFEK`/`DecryptFEK` functions, or
2. Delete the unused `EncryptFEK`/`DecryptFEK`/`EncryptFile`/`DecryptFile` from `crypto/file_operations.go` since they're not the source of truth.

Recommend (1): a single shared implementation across server, CLI, and tests is the AGENTS.md §"Use Cases & Consistency" guidance.

**Cross-refs.** AGENTS.md §"Use Cases & Consistency".

---

### Finding B-18: Comment-only `crypto/envelope.go` file (essentially dead)

- Severity: **Informational**
- Confidence: High
- Category: hygiene
- Component: `crypto/envelope.go`

**Description.** The entire 22-line file contains only a comment describing the envelope format. The same comment is duplicated verbatim in `crypto/file_operations.go:239-258`. Code-wise it's a no-op.

**Recommendation.** Delete `crypto/envelope.go` (the comment in `file_operations.go` is sufficient), or move the envelope-related code (`CreateEnvelope`, `ParseEnvelope`) from `file_operations.go` into `envelope.go` to give it a real purpose.

---

### Finding B-19: Password requirements also fetched from server unauthenticated — same downgrade pattern as B-01/B-03

- Severity: **Medium**
- Confidence: High
- Category: cryptographic / policy
- Component: `client/static/js/src/crypto/password-validation.ts:30-46`

**Description.** The client fetches `/api/config/password-requirements` for length/class minima. A malicious server can return `{minAccountPasswordLength: 1, minSharePasswordLength: 1, minCharacterClassesRequired: 0, ...}`. The client will then accept weak passwords from the user during registration/share-creation, which subsequently get fed into Argon2id (which can also have been downgraded — B-01). The resulting KEK is trivially crackable.

**Evidence.**

```
const response = await fetch('/api/config/password-requirements');
// ... no validation of returned values
```

**Attack scenario.** Same pattern as B-01.

**Impact.** Medium. On its own, downgraded password policy only weakens **new** passwords (the user types something the client says is acceptable). Combined with B-01, this gives the malicious server a 2x lever to force trivial-to-crack credentials.

**Recommendation.** Hard-code a floor in the client (e.g. `minAccountPasswordLength >= 15`, `minCharacterClassesRequired >= 2`) and refuse anything less. Same hardening pattern as B-01/B-03.

**Cross-refs.** B-01, B-03.

---

### Finding B-20: `password.length` (JS) vs `len(password)` (Go) — Unicode length mismatch in password validation

- Severity: **Low**
- Confidence: High
- Category: cross-platform consistency
- Component: `crypto/password_validation.go` vs `client/static/js/src/crypto/password-validation.ts`

**Description.** Go's `len(password)` returns UTF-8 byte length. JS's `password.length` returns UTF-16 code-unit count. For non-BMP characters (e.g. emojis, many CJK rare characters), these differ:

- Single non-BMP code point = 1 byte (no — won't fit), actually 4 UTF-8 bytes, 2 UTF-16 code units.
- A 15-emoji password is 60 bytes in Go (passes Go's `length >= 15` check) but 30 UTF-16 code units in JS (passes JS's `length >= 15` check). Consistent enough.
- A 7-character BMP-only password is 7 bytes in Go and 7 code units in JS. Consistent.
- A 7-character password containing 1 emoji is 6 + 4 = 10 bytes in Go and 6 + 2 = 8 code units in JS. **The client-side check `length >= 15` rejects 8; the server side gets a 10-byte string and would also reject `len >= 15`**, so the actual rejection condition is consistent here too.

The mismatch DOES bite at the **other** end: `maxPasswordLength: 256` in Go means 256 bytes (≤ 256 BMP chars or ≤ 64 emojis). In JS, `length <= 256` means 256 UTF-16 code units (≤ 256 BMP chars or ≤ 128 emojis). So a 200-emoji password is 800 bytes — rejected by Go's max check but accepted by JS's. The JS client would let the user submit it, then the server would reject. This is a UX inconsistency rather than a security one (the server is the final enforcer), but it leaks an artifact about the encoding to the user.

A more practical risk: Go's character-class check uses ASCII ranges:
```
case char >= 'A' && char <= 'Z':
case char >= 'a' && char <= 'z':
case char >= '0' && char <= '9':
default:
    if strings.ContainsRune(specialChars, char) { hasSpecial = true }
```
Unicode letters (e.g. "ü", "中", "α") don't match upper/lower/number; they only contribute to "special" if listed in `specialChars`. They aren't, so a Unicode-only password counts as zero character classes, fails the `minCharacterClassesRequired: 2` check. **JS has the same ASCII-only check** (`code >= 65 && code <= 90` etc), so behavior is consistent — but both treat international users as second-class.

**Attack scenario.** Not an attack. Honesty/UX issue. Users with international passwords get confusing errors.

**Impact.** Low. UX consistency.

**Recommendation.**

1. Document explicitly that password length is byte/code-unit based and may differ for non-BMP characters; recommend using rune/codepoint count in both Go (`utf8.RuneCountInString`) and JS (`[...password].length`).
2. Either extend the character-class definition to include Unicode "Letter" categories (`unicode.IsUpper`/`IsLower`/`IsDigit` in Go, `\p{Lu}`/`\p{Ll}`/`\p{Nd}` regex in JS), or document the ASCII-only limitation in the user-visible policy text.

**Cross-refs.** Slice A finding on Unicode normalization of usernames (separate but related).

---

### Finding B-21: Account-key-cache `secureWipe` overwrites with random then zero — defense-in-depth, but JS GC may have already copied

- Severity: **Informational**
- Confidence: Medium
- Category: cryptographic / hygiene
- Component: `client/static/js/src/crypto/primitives.ts:443-449`

**Description.** `secureWipe` does:
```
crypto.getRandomValues(data as unknown as Uint8Array<ArrayBuffer>);
data.fill(0);
```

This is good practice for the buffer in question, BUT in JS, every time a `Uint8Array` is passed to `crypto.subtle.importKey`, `crypto.subtle.encrypt`, etc., the contents may be **copied** by the runtime into internal buffers that are inaccessible from JS and not wiped. The JS heap-management is also a GC pile — there's no guarantee that intermediate string buffers (e.g. `JSON.stringify(envelope)` in `cacheAccountKey`) get wiped before being garbage-collected.

**Evidence.** Pattern is documented in many crypto-in-JS treatises; not specific to Arkfile.

**Attack scenario.** A browser-process memory dump (post-XSS, post-extension-compromise, post-OS-memory-leak) may still find copies of recently-used keys / passwords / FEKs in the heap. `secureWipe` doesn't help against this.

**Impact.** Informational. The cache's design (encrypted-at-rest in sessionStorage, wrapping key in a single `let wrappingKey` variable that *is* wiped) is a sensible best-effort. Improvements would require browser-API changes Arkfile cannot make.

**Recommendation.** Document the limitation in `account-key-cache.ts` comments so future readers don't believe `secureWipe` is bulletproof. Already acknowledged in code via "best-effort" comments — but a more explicit statement is warranted.

**Cross-refs.** None.

---

### Finding B-22: `account-key-cache.ts` uses an emoji in `console.error` — violates AGENTS.md §"No Emojis"

- Severity: **Informational**
- Confidence: High
- Category: hygiene
- Component: `client/static/js/src/crypto/account-key-cache.ts:385`

**Description.** Line reads:

```
console.error('⚠️ Account key cache integrity check failed! Possible tampering detected. Locking.');
```

AGENTS.md §"No Emojis" explicitly prohibits this.

**Recommendation.** Replace `⚠️` with `[!]` per AGENTS.md.

---

### Finding B-23: TS `EncryptedFileMetadata` interface is declared twice in `types.ts`

- Severity: **Informational**
- Confidence: High
- Category: hygiene
- Component: `client/static/js/src/crypto/types.ts:126-138` and `:234-252`

**Description.** Two different shapes of the `EncryptedFileMetadata` interface are declared in the same file. The second declaration shadows the first (or the union is computed depending on TS version). Both appear unused in the codebase (no other file imports `EncryptedFileMetadata`).

**Recommendation.** Delete the duplicate. Likely both can go since they're unused.

---

### Finding B-24: Go `DeriveAccountPasswordKey` / `DeriveCustomPasswordKey` discard the error from `DeriveArgon2IDKey`

- Severity: **Informational**
- Confidence: High
- Category: hygiene
- Component: `crypto/key_derivation.go:143-154`

**Description.**

```
func DeriveAccountPasswordKey(password []byte, username string) []byte {
    salt := GenerateUserKeySalt(username, "account")
    key, _ := DeriveArgon2IDKey(password, salt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
    return key
}
```

The `_` ignores any error. The only realistic error paths in `DeriveArgon2IDKey` are empty/oversized password and empty/zero-keyLen — but the salt is always 32 bytes, keyLen is set from a validated config, and the password is the caller's responsibility. If `password` is empty or > `MaxPasswordBytes`, the function returns `nil` silently. Subsequent code paths that use `key` will then call `aes.NewCipher(nil)` and panic.

**Attack scenario.** A caller bug (passing an empty password) becomes a panic rather than a clear error. Not an attack, but error-handling hygiene.

**Recommendation.** Either propagate the error (change return signature to `([]byte, error)`) or add an explicit `panic` if the caller passed a clearly invalid input.

---

### Finding B-25: `KeyManager.StoreKey` uses `REPLACE INTO` — silently overwrites existing keys

- Severity: **Informational**
- Confidence: High
- Category: operational
- Component: `crypto/key_manager.go:226-244`

**Description.** `REPLACE INTO system_keys ...` will silently overwrite an existing row with the same `key_id`. If somewhere in the code a programmer accidentally calls `StoreKey("jwt_signing_key_v1", "jwt", newKey)`, the old key is gone with no warning — all tokens signed under the old key become unverifiable.

**Evidence.** Quoted above.

**Attack scenario.** Not an attack. Operational risk: a code bug or admin tool misuse silently rotates system keys.

**Recommendation.**

1. Use `INSERT INTO ... ON CONFLICT (key_id) DO UPDATE` only when intent is "rotate". Otherwise use plain `INSERT` and surface the conflict.
2. Audit log every `StoreKey` call with the old hash and new hash of the encrypted blob (or a `WARNING` log line that says "system key <id> was overwritten").

---

### Finding B-26: `KeyManager.deriveWrappingKey` uses HKDF-Expand on a high-entropy master key — acceptable, but Extract+Expand would be more conventional

- Severity: **Informational**
- Confidence: High
- Category: cryptographic / design
- Component: `crypto/key_manager.go:77-86`

**Description.**

```
info := []byte(fmt.Sprintf("ARKFILE_%s_KEY_ENCRYPTION", keyType))
reader := hkdf.Expand(sha256.New, km.masterKey, info)
```

`hkdf.Expand` skips the Extract step. This is mathematically fine when the input keying material is already uniformly random (32 bytes from `crypto/rand`), but textbook RFC 5869 use is `Extract -> Expand`. The non-conventional skip means a code reviewer needs to know the master-key entropy claim to evaluate safety.

A second, very minor concern: the `keyType` substring goes directly into the info string with no length prefix or delimiter beyond underscores. `keyType="jwt"` and `keyType="jwt_v2"` produce different info strings, but a hypothetical `keyType="jwt_KEY_ENCRYPTION"` would collide with `keyType="jwt"` in a specific way. No current callers use such a keyType, so this is theoretical.

**Recommendation.**

1. Use `hkdf.New(sha256.New, masterKey, salt=nil, info=info)` (i.e. full Extract+Expand). Functionally near-identical for high-entropy inputs but matches the RFC and reduces reviewer load.
2. Add a leading and trailing length-prefix or sentinel to `keyType` in the info string.

---

### Finding B-27: Client-side `MAX_FILE_SIZE: 5 GB` contradicts the AGENTS.md mobile-constraint example of "6 GB on 3 GB RAM"

- Severity: **Informational**
- Confidence: High
- Category: design / consistency
- Component: `client/static/js/src/crypto/constants.ts:261-262`

**Description.** AGENTS.md gives the canonical example: "a user on a mobile device with 3 GB of RAM, attempting to encrypt/decrypt/upload/download a 6 GB file". The client-side hard cap is 5 GB. A 6 GB file would be rejected client-side even though the streaming-chunk design makes the operation memory-feasible.

**Recommendation.** Raise the cap to ≥ 6 GB, or document the constraint mismatch. Memory feasibility is governed by the 16 MiB chunk size, not the total-file-size cap.

---

## 3. Tables

### 3.1 Cryptographic Review Table

| Operation | Primitive | Key source | Nonce/IV handling | Associated data | Storage location | Issues |
|---|---|---|---|---|---|---|
| Account-KEK derivation | Argon2id (m=64MiB, t=3, p=1, dk=32) | account password (user-typed) | salt = SHA-256("arkfile-account-key-salt:" + username), 32 B deterministic | n/a | derived in client RAM; cached encrypted in sessionStorage | B-01 (server-controlled params), B-07 (KEK reused as metadata key) |
| Custom-KEK derivation | Argon2id same params | custom password | salt = SHA-256("arkfile-custom-key-salt:" + username), 32 B deterministic | n/a | derived in client RAM only (no caching) | B-01 |
| Share-KEK derivation | Argon2id same params | share password | random 32 B per share, server-stored | n/a | derived in recipient RAM only | B-01, B-04 (UI block) |
| FEK generation | `crypto/rand` (Go) / `crypto.getRandomValues` (TS) | n/a | n/a | n/a | random 32 B per file, never persisted plaintext | none |
| File chunk encryption | AES-256-GCM | FEK | 12 B random per chunk via `crypto.subtle` / `crypto/rand` | **NONE** | nonce \|\| ct \|\| tag, uploaded to S3 | **B-02 (no AAD => file/chunk substitution)**, B-05 (reorder/truncate) |
| FEK envelope encryption | AES-256-GCM | Account-KEK or Custom-KEK | 12 B random | **NONE** | `[0x01][keytype][nonce][ct][tag]`, DB column `encrypted_fek` | B-08 (no AAD) |
| File metadata encryption (filename, sha256-hex) | AES-256-GCM | Account-KEK directly | 12 B random per field | **NONE** | nonce + (ct\|\|tag) in separate DB columns per field | B-07, B-13 |
| Share envelope encryption | AES-256-GCM | Share-KEK | 12 B random | **utf8(shareID + fileID)** | nonce \|\| ct \|\| tag in DB | B-15 (AAD concat) |
| Server-side padding | random bytes appended to last chunk | n/a | n/a | n/a (not authenticated) | last chunk on S3 | B-06 (server sees pre-padding size) |
| System key wrap | AES-256-GCM | `HKDF-Expand(ARKFILE_MASTER_KEY, "ARKFILE_<type>_KEY_ENCRYPTION")` | 12 B random | none | DB table `system_keys`, columns `encrypted_data` + `nonce`, hex-encoded | B-16 (env-var master key), B-25 (REPLACE INTO), B-26 (Expand-only) |
| Account-key cache wrap (sessionStorage) | AES-256-GCM + HMAC-SHA256 integrity | ephemeral random 32 B in JS heap | 12 B random | none on AEAD; HMAC over ciphertext | sessionStorage (encrypted) + ephemeral wrappingKey (RAM) | well-designed; B-21 (JS GC residue caveat), B-22 (emoji) |

### 3.2 Key Hierarchy

**Tier 0 — User secrets (never leave the client unless they are passwords typed into OPAQUE; passwords typed for file encryption never leave the client).**

- Account password — user-typed. Two purposes, cryptographically separated:
  - Fed to OPAQUE (Slice A) for authentication.
  - Fed to Argon2id for Account-KEK derivation (this slice).
- Custom password — user-typed when file uses 0x02 key-type byte. Argon2id only.
- Share password — user-typed when creating a share; recipient types it to open. Argon2id only.

**Tier 1 — Derived from Tier 0 by client-side Argon2id.**

| Key | Derived how | Length | Where stored | Leaves client? | What it encrypts/authenticates | Rotation | Destruction | Compromise impact |
|---|---|---|---|---|---|---|---|---|
| Account-KEK | Argon2id(account_pwd, salt=det(username,"account")) | 32 B | Client RAM; optionally AES-wrapped in sessionStorage | No | (a) wraps account-context FEKs, (b) encrypts all metadata for that user's files | Implicitly rotates on password change (rederives) | `secureWipe` best-effort | All this user's account-encrypted file metadata and FEKs decryptable |
| Custom-KEK | Argon2id(custom_pwd, salt=det(username,"custom")) | 32 B | Client RAM only | No | Wraps custom-context FEKs | Per-password change | RAM-only, naturally dies on tab close | This user's custom-encrypted FEKs decryptable |
| Share-KEK | Argon2id(share_pwd, salt=random32 per share) | 32 B | Recipient RAM only | No | The share envelope | Per share | RAM-only | Only the one share's FEK + download token |

**Tier 2 — Random per-file/per-share.**

| Key | Generated how | Length | Where stored | Leaves client? | What it encrypts | Rotation | Destruction | Compromise impact |
|---|---|---|---|---|---|---|---|---|
| FEK (File Encryption Key) | `crypto/rand` or `getRandomValues` | 32 B | Client RAM during operation; wrapped under KEK; never persisted plaintext | No (only encrypted forms reach server) | All chunks of one file | Never rotated within a file's lifetime (a share keeps the same FEK so revocation has no cryptographic teeth without re-encryption) | RAM-only after use | The one file's content |
| Download Token | `crypto/rand` | 32 B | Client RAM, embedded in share envelope; **SHA-256 hash** stored on server | Only as plaintext to the recipient via the envelope, never to server in plain | Authorizes server-side delivery of the share's file chunks | Per share, regenerable | RAM-only | Anyone with the token can fetch the encrypted chunks (still need FEK to decrypt) |
| Share-salt | `crypto/rand` | 32 B | Server (per share row), base64 | Yes (public) | Salt for Share-KEK derivation | Per share | Server-side persistent | Public, no confidentiality value |

**Tier 3 — Server-managed system secrets (wrapped by `crypto/key_manager.go`).**

| Key | Generated how | Length | Where stored | Leaves server? | What it encrypts/signs | Rotation | Destruction | Compromise impact |
|---|---|---|---|---|---|---|---|---|
| ARKFILE_MASTER_KEY | Generated once at deploy time by `scripts/setup`; operator-managed | 32 B | `/opt/arkfile/etc/secrets.env` env var; loaded into process memory | No | HKDF source for all wrapping subkeys | Manual key-rotation procedure (not automated) | Process death | Catastrophic: every system key decryptable from DB + master key |
| JWT signing key | `crypto/rand` via `KeyManager.GetOrGenerateKey("jwt_signing_key_v1","jwt",64)` | 64 B | DB `system_keys`, encrypted under master-derived wrapping key | No | JWT signatures (Slice A) | Manual via `scripts/maintenance/rotate-jwt-keys.sh` | DB row delete | Token forgery (Slice A) |
| TOTP master key | Same pattern (`"totp_master_key_v1","totp",64`) | 64 B | DB `system_keys` | No | Per-user TOTP secret encryption via HKDF subkeys (Slice A) | Manual | DB row delete | All TOTP secrets recoverable (Slice A) |
| OPAQUE server setup key | Generated by libopaque, wrapped by KeyManager (Slice A) | per libopaque | DB `system_keys` | No | OPAQUE protocol server-side state (Slice A) | Manual / never | DB row delete | OPAQUE auth break (Slice A) |

### 3.3 Metadata Exposure Matrix (Slice B columns)

Slice G will finalize the matrix with input from Slices C/D for "Visible to server?" and "Notes". Slice B contributes the "Encrypted?" and "Authenticated?" columns.

| Metadata item | Encrypted? | Authenticated (AEAD AAD bound to file_id)? | Notes |
|---|---|---|---|
| Filename | Yes (AES-GCM under Account-KEK) | **No** (no AAD) | Metadata-key == Account-KEK (B-07). Server-swappable between this user's files (B-02). |
| SHA-256 of plaintext (hex) | Yes (AES-GCM under Account-KEK) | **No** | Same as above. |
| File size (declared, unpadded) | **No** | n/a | Stored in `upload_sessions.total_size` and `file_metadata.size_bytes`. Server learns exact ciphertext size before padding (B-06). |
| Padded size on S3 | **No** | n/a | Stored in `file_metadata.padded_size`. Leaks ~2.2% of plaintext size to bucket observers. |
| Upload time / modified time | **No** | n/a | Standard DB timestamps (Slice C/E). |
| Owner username | **No** | n/a | Required for ACL / KEK derivation. (Slice E.) |
| Number of files per user | **No** | n/a | Trivially queryable. (Slice E.) |
| Chunk count | **No** | n/a | Derivable from `total_size / chunk_size`. |
| Storage provider routing (which S3 backend) | **No** | n/a | (Slice C.) |
| Share recipient identity | **n/a** | n/a | Sharing is anonymous; no recipient identity persisted. (Slice D.) |
| Share password hint | optional plaintext | n/a | If set, plaintext stored by server (Slice D). |
| Share file_id ↔ share_id mapping | **No** | n/a | Public; mapping is required for AAD construction (B-15). |
| MIME type | **No** | n/a | Not stored; the server's HTTP layer infers from `Content-Type` on download response or sniff. (Slice C / Slice F.) |
| Folder path | n/a | n/a | Arkfile has no folders. |

---

## 4. N/A items for this slice

| Item from `idsrp.md` | Status | Justification |
|---|---|---|
| Recipient public-key authentication (PKI) | N/A | Arkfile sharing is password-based, not PKI-based. Pre-confirmed in plan. |
| Server-side search index / thumbnails | N/A | Files are encrypted blobs; no preview/search infrastructure. |
| Folder-level key hierarchy / hierarchy crypto | N/A | Flat per-user file space. |
| Argon2 variant other than Argon2id | N/A | Variant validated to `Argon2id` at load (`crypto/key_derivation.go:51-53`). |
| Recipient public-key substitution by server | N/A | No public-key directory exists. |
| Cross-tenant key isolation | N/A | Single-tenant. |
| MAC-then-encrypt vs encrypt-then-MAC | N/A | AES-GCM is AEAD; question doesn't apply. |
| Stream cipher counter wraparound | N/A | AES-GCM ICB counter cannot wrap within a single 16 MiB chunk (2^32 blocks of 16 B per chunk = 64 GiB; 16 MiB ≪ 64 GiB). |

---

## 5. Open questions / blocked-on-developer items

1. **Is the deliberate decision to not bind `file_id` into the file-chunk AEAD documented anywhere?** Slice B treats it as a serious finding (B-02). If there's a design rationale (e.g. enabling chunk deduplication across files), please flag.
2. **What is the planned key-rotation cadence for system keys?** B-25 surfaces a `REPLACE INTO` concern; if rotation is intended monthly/yearly, we need an audit-logged rotation pathway, not silent overwrite.
3. **Is the `ARKFILE_MASTER_KEY` env var ever read from anywhere other than `/opt/arkfile/etc/secrets.env`?** (I have not read that file per `.clinerules`.) If it's also kept in a backup, the backup itself becomes a critical asset.
4. **Should Arkfile bundle Argon2id WASM (vs continuing with pure-JS `@noble/hashes`) for Slice B-04 fix?** If yes, Slice F needs to add SRI/pinning for that WASM artifact.
5. **Is the client-side `MAX_FILE_SIZE` cap of 5 GB intentional (B-27) or a leftover from before the streaming-chunk rewrite?** The AGENTS.md 6-GB-on-3-GB-RAM constraint implies it should be higher.
6. **For the "metadata-key == Account-KEK" choice (B-07): is there a roadmap to derive separate subkeys via HKDF?** If so, B-07 can be reframed as a planned change rather than a finding.

---

## 6. Testing gaps identified (feed into Slice G)

Listed in priority order; each gap maps to one or more findings.

| # | Gap | Maps to | Suggested test type |
|---|---|---|---|
| 1 | No test of "client refuses weak server-supplied Argon2id params" | B-01 | Jest mock of `/api/config/argon2` returning weak params; assert refusal |
| 2 | No test of "client refuses weak server-supplied chunking params" | B-03 | Jest mock of `/api/config/chunking` |
| 3 | No test of "client refuses weak server-supplied password requirements" | B-19 | Jest mock |
| 4 | No test of file-chunk reorder/truncate/duplicate (currently undetectable cryptographically) | B-02, B-05 | After AAD fix lands: property test against the new AAD scheme |
| 5 | No test of cross-file FEK swap within the same user | B-02, B-08 | After AAD fix: encrypt two files with same Account-KEK, swap encrypted-FEK blobs, assert decryption fails |
| 6 | No test of "server cannot recover original plaintext size from padded ciphertext within X bits" | B-06 | Statistical / property test of `CalculatePaddedSize` over many sizes |
| 7 | No test of Argon2id parameter mismatch between Go and TS | B-01 | Cross-language test: same password+salt+params -> same key byte-for-byte |
| 8 | No test of "session.go is unused" — once deleted, build-fails on accidental re-import | B-10 | Just delete the file; CI catches re-import |
| 9 | No test that DEBUG_MODE prints nothing in production builds | B-12 | Build-tag-conditional compilation + test that asserts log output is empty when not in debug |
| 10 | No test of AAD-concat collision resilience for `CreateAAD` | B-15 | Construct adversarial (shareID, fileID) pairs and assert different AAD outputs |
| 11 | No fuzz test of envelope parser (`ParseEnvelope`, `DecryptFEK`) on malformed inputs | hardening | `go test -fuzz` corpus |
| 12 | No test of `EncryptGCM` empty-plaintext / `EncryptFile` empty-plaintext consistency | B-14 | Trivial unit test |
| 13 | No test that `getUserFriendlyMessage`'s 5 GB string stays in sync with `LIMITS.MAX_FILE_SIZE` | hygiene | Simple string-vs-constant test |
| 14 | No test of nonce-uniqueness across many encryptions under the same key (birthday-bound smoke test) | hardening | Statistical test |
| 15 | No test of `secureWipe` on a Uint8Array backing a SharedArrayBuffer (edge case) | B-21 | Edge-case unit test |

---

## 7. Hardening / non-vulnerability recommendations

Non-finding recommendations (not security bugs, but improvements):

1. **Adopt typed-key wrappers in Go.** `[]byte` everywhere makes it easy to accidentally use a KEK where a metadata key is wanted. Define `type AccountKEK [32]byte`, `type CustomKEK [32]byte`, `type ShareKEK [32]byte`, `type FEK [32]byte`, `type MetadataKey [32]byte`. The compiler then catches misuse statically. Same pattern in TS via branded types.

2. **Embed `argon2id-params.json` into the TS build** (esbuild / bun's `--external` / inline JSON import) so it's a compile-time constant the way the Go side is. Remove the `/api/config/argon2` endpoint entirely from the security-critical path.

3. **Cross-language conformance test in CI.** A Go test program that emits a JSON file `{password, username, expected_account_kek_hex, expected_custom_kek_hex, ...}` plus a TS test that consumes the same file and asserts the derived key matches. Prevents future drift.

4. **Document the file-identity authenticity gap honestly in `docs/privacy.md`.** Until B-02 is fixed, the docs should say: "Arkfile guarantees confidentiality of file *content* from the server, but does not currently guarantee that the file you download is the file you requested. We are working on file-identity authenticity (see ticket)."

5. **Add a "crypto agility version" byte to every encrypted artifact** — already present as `0x01` envelope-version. When B-02 lands as `0x02`, the dispatch is automatic. Make sure the parser **rejects** unknown versions rather than treating them as 0x01.

6. **Property-test the padding ladder.** Choose a real file-size distribution from public corpora (e.g. Wikipedia file sizes, common-doc-sizes) and compute the information-theoretic leakage of the current 2%-block scheme. Document the result.

7. **Consider adopting RFC 8439 ChaCha20-Poly1305 for chunks.** AES-GCM is fine on modern hardware with AES-NI but suffers a ~2x slowdown on ARM without AES extensions (some mobile chips). ChaCha20 is constant-time everywhere and faster on those devices. Not a finding — just a future consideration.

8. **Add explicit zeroization helpers in Go that the compiler won't optimize away.** `SecureClear` is a plain `for-range` loop; modern Go compilers may eliminate it. Use `runtime.KeepAlive` or `crypto/subtle.ConstantTimeByteEq` patterns to prevent dead-store elimination.

9. **Move the comment in `crypto/envelope.go` into actual code** by relocating `CreateEnvelope`/`ParseEnvelope` from `file_operations.go` into `envelope.go`. The current organization is "the file named `envelope.go` has no envelope code; the file named `file_operations.go` has envelope code".

10. **For B-26's HKDF-Expand-only pattern**: even though it's mathematically safe with high-entropy keys, the RFC-conventional `hkdf.New(...)` (Extract+Expand) is one line of code; using it makes the reviewer's job easier.

---

## Severity summary

| Severity | Count | Findings |
|---|---:|---|
| Critical | 0 | — |
| High | 3 | B-01, B-02, B-03 |
| Medium | 6 | B-04, B-05, B-06, B-07, B-08, B-19 |
| Low | 10 | B-09, B-10, B-11, B-12, B-13, B-14, B-15, B-16, B-17, B-20 |
| Informational | 8 | B-18, B-21, B-22, B-23, B-24, B-25, B-26, B-27 |
| **Total** | **27** | B-01..B-27 |

(Severity counts use the strict severity tag on each finding. The Medium-vs-Low boundary on B-08 and B-19 is judged in favor of the higher class because they are part of broader downgrade or substitution patterns that magnify their individual impact.)

Top three risks (Slice B contribution to the eventual executive summary):

1. **B-01 / B-03 / B-19 — server-controlled crypto parameters**. A compromised server can silently weaken every future Argon2id derivation, chunk encryption, and password-policy check. Fix: embed all parameter floors in the client bundle.
2. **B-02 / B-05 / B-08 — no AAD on file/chunk/FEK encryption**. A malicious server can swap one of a user's own files for another with full integrity verification still passing. Fix: bind `file_id` and chunk index into AEAD AAD for every file-related encryption.
3. **B-06 — server-applied padding**. Padding policy is operationally meaningful only against bucket-only adversaries; the server itself sees the unpadded ciphertext size, which AGENTS.md implies it should not. Fix: client-side padding before upload.
