# Phase C — Step 0 Range-Math Audit

**Status:** Audit complete, awaiting developer decision before Step 1.

This document is the deliverable for §9 Step 0 of `phase-c.md`. It maps every surface that does byte-range arithmetic on encrypted chunks, classifies whether the chunk-0 `[version][keyType]` two-byte header can be removed cleanly, and presents an Outcome A vs. Outcome B recommendation.

The invariant being validated everywhere is:

> Padding exists only after the encrypted stream and must never be included in any decrypted chunk range. Final chunk ranges are bounded by `total_size` (= the encrypted-stream byte count), not `padded_size`.

---

## 1. Surface inventory

Six surfaces touch chunk layout or chunk byte-range math.

### 1.1 Server upload init — `handlers/uploads.go`

`CreateUploadSession` (lines ~99–134):

```go
const aesGcmOverheadBytes = 28 // nonce(12) + tag(16)
const envelopeHeaderBytes = 2  // version(1) + keyType(1), prepended to chunk 0 only
encryptedChunkSize := int64(request.ChunkSize) + aesGcmOverheadBytes
effectiveEncryptedSize := request.TotalSize - envelopeHeaderBytes
if effectiveEncryptedSize <= 0 {
    effectiveEncryptedSize = encryptedChunkSize // empty file: at least 1 chunk
}
totalChunks := (effectiveEncryptedSize + encryptedChunkSize - 1) / encryptedChunkSize
```

The server computes `totalChunks` from the client-declared encrypted total by:
1. Subtracting the one-time 2-byte chunk-0 envelope header.
2. Dividing by the per-chunk size (`plaintext + 28 GCM overhead`).

`UploadChunk` (lines ~534–566) validates chunk-0 size differently from chunks 1+: chunk 0 must include `envelopeSize + gcmOverhead + 1` minimum bytes, chunks 1+ must include `gcmOverhead + 1` minimum.

**Padding interaction:** server appends random bytes to the last chunk only when `paddedSize > totalSize` (lines ~602–612). Padding is uploaded as part of the last S3 part, never as a separate range.

**Removing the header would require:** changing `effectiveEncryptedSize := request.TotalSize` (drop the `- 2`); switching `UploadChunk`'s chunk-0 minimum to `gcmOverhead + 1`; removing the `if chunkNumber == 0` branch in `UploadChunk`'s validation.

### 1.2 Server owner download — `handlers/downloads.go`

`DownloadFileChunk` (lines ~61–102):

```go
chunk0EncSize := envelopeHeader + gcmOverhead + plaintextChunkSize
regularEncSize := gcmOverhead + plaintextChunkSize

var startByte, encChunkSize int64
if chunkIndex == 0 {
    startByte = 0
    encChunkSize = chunk0EncSize
} else {
    startByte = chunk0EncSize + (chunkIndex-1)*regularEncSize
    encChunkSize = regularEncSize
}

endByte := startByte + encChunkSize - 1
```

The byte-range is calculated against the stored object's encrypted offsets, then capped by `file.SizeBytes` (line 94/99) to handle the last (possibly partial) chunk. **The cap correctly uses `file.SizeBytes` (encrypted-stream length) and never reaches into `file.PaddedSize`.**

**Removing the header would require:** dropping the `chunk0EncSize` distinction. Math becomes uniform:

```go
startByte = chunkIndex * regularEncSize
encChunkSize = regularEncSize
```

### 1.3 Server anonymous share download — `handlers/file_shares.go`

`DownloadShareChunk` (the second of two surfaces in that file). The chunk-0 vs. chunks-1+ math is **byte-for-byte identical** to `handlers/downloads.go`:

```go
chunk0EncSize := envelopeHeader + gcmOverhead + chunkSizeBytes
regularEncSize := gcmOverhead + chunkSizeBytes

if chunkIndex == 0 {
    startByte = 0
    encChunkSize = chunk0EncSize
} else {
    startByte = chunk0EncSize + (chunkIndex-1)*regularEncSize
    encChunkSize = regularEncSize
}
endByte := startByte + encChunkSize - 1
if endByte >= sizeBytes {
    endByte = sizeBytes - 1
}
```

Final-chunk cap is `sizeBytes` (encrypted-stream length), not `padded_size`. Identical to the owner path.

`GetShareDownloadMetadata` (the first surface in that file) just returns `chunk_count` and `chunk_size_bytes` from the file metadata row; no range math.

### 1.4 Browser upload — `client/static/js/src/files/upload.ts`

Two pieces of header-aware code.

**`calculateTotalEncryptedSize` (lines ~406–427):**

```ts
function calculateTotalEncryptedSize(
  plaintextSize, chunkSize, overhead, headerSize
): number {
  if (plaintextSize === 0) {
    return headerSize + overhead;
  }
  const numFullChunks = Math.floor(plaintextSize / chunkSize);
  const lastChunkPlaintext = plaintextSize % chunkSize;
  if (lastChunkPlaintext === 0) {
    return numFullChunks * (chunkSize + overhead) + headerSize;
  }
  return numFullChunks * (chunkSize + overhead) + (lastChunkPlaintext + overhead) + headerSize;
}
```

Mirrors Go-side CLI.

**Per-chunk upload loop (lines ~670–676):**

```ts
let chunkToUpload: Uint8Array;
if (i === 0) {
  const chunkEnvelope = createEnvelopeHeader(envelopeVersion, keyTypeVal);
  chunkToUpload = concatBytes(chunkEnvelope, encryptedChunk);
} else {
  chunkToUpload = encryptedChunk;
}
```

**Removing the header would require:** `calculateTotalEncryptedSize` drops the `+ headerSize` term; the per-chunk loop drops the `if (i === 0)` branch.

### 1.5 Browser streaming download — `client/static/js/src/files/streaming-download.ts`

Two near-identical generators (file owner + anonymous share recipient), lines ~321–392 and ~395–466. Both strip the 2-byte envelope header from chunk 0 only:

```ts
let chunkData = encryptedChunk;
if (chunkIndex === 0) {
  if (encryptedChunk.length < envelopeHeaderSize) {
    throw new Error(`Chunk 0 too short: …`);
  }
  const version = encryptedChunk[0];
  if (version !== 0x01) {
    throw new Error(`Unsupported envelope version on chunk 0: …`);
  }
  chunkData = encryptedChunk.slice(envelopeHeaderSize);
}
const decryptedChunk = await decryptor.decryptChunk(chunkData);
```

`calculateTotalEncryptedSize` in this file (line 576) is wrong-leaning today (`size_bytes + total_chunks * aesGcmOverhead`) — it does NOT add the envelope header. It is only used for progress UI %, so the inaccuracy is cosmetic. Nothing in the actual download path depends on it.

**Removing the header would require:** dropping the chunk-0 special case in both generators; updating `streaming-download.test.ts`'s `addEnvelopeHeader` helper (lines ~95–110 area) — the test helper exists only to *construct* an envelope to feed the SUT, so it gets deleted, not updated.

### 1.6 CLI — `cmd/arkfile-client/`

Four sub-surfaces:

**`crypto_utils.go encryptChunk(plaintext, fek, chunkIndex, keyType)`:**

```go
if chunkIndex == 0 {
    header := []byte{0x01, keyType} // version 1 + key type
    return append(header, encryptedChunk...), nil
}
return encryptedChunk, nil
```

**`crypto_utils.go decryptChunk(data, fek, chunkIndex)`:**

```go
if chunkIndex == 0 {
    headerSize := crypto.EnvelopeHeaderSize()
    if len(data) < headerSize {
        return nil, fmt.Errorf("chunk 0 too short")
    }
    data = data[headerSize:]
}
// then AES-GCM decrypt
```

**`commands.go calculateTotalEncryptedSize`:** identical to TS version. Uses `crypto.EnvelopeHeaderSize()`.

**`offline_decrypt.go decryptBundleBlob` (lines ~317–354):** the only surface in the entire codebase that does range arithmetic on a sequential read (not an HTTP byte-range). It iterates chunks reading `plaintextChunkSize + overhead + (envelopeHeader if chunkIndex == 0)` bytes at a time, decrements `remaining = meta.SizeBytes`, and stops when `remaining == 0`.

**`commands.go doChunkedUpload`:** loops, calls `encryptChunk(plaintext, fek, chunkIndex, keyType)` — the header concern is encapsulated inside `encryptChunk`.

**`commands.go doChunkedDownload`:** loops `chunkIndex := 0..ChunkCount-1`, calls `decryptChunk(data, fek, chunkIndex)` — header concern is encapsulated inside `decryptChunk`.

**Removing the header would require:** `crypto_utils.go encryptChunk` drops the `if chunkIndex == 0` branch (just returns `[nonce][ct][tag]`); `decryptChunk` drops it too; `commands.go calculateTotalEncryptedSize` drops `+ headerSize`; `offline_decrypt.go decryptBundleBlob` simplifies its loop (no per-chunk overhead variability).

### 1.7 Export bundle — `handlers/export.go`

The export bundle wraps the **already-padded** S3 object verbatim (lines ~268–326):

```go
blobSize := file.SizeBytes
if file.PaddedSize.Valid && file.PaddedSize.Int64 > 0 {
    blobSize = file.PaddedSize.Int64
}
// ...
io.Copy(writer, s3Object)  // streams the whole padded object
```

The bundle JSON metadata carries both `size_bytes` (encrypted-stream length) and `padded_size`. `cmd/arkfile-client/offline_decrypt.go decryptBundleBlob` reads exactly `meta.SizeBytes` bytes from the blob, leaving the padding bytes unread (they are at the tail of the blob, after the last encrypted chunk). **The padding-vs-encrypted invariant holds end-to-end.**

The bundle metadata has every field Phase C needs **except `owner_username`** (per §6.1 of `phase-c.md`).

---

## 2. Invariant verification: "padding only after the encrypted stream"

All six surfaces respect this:

| Surface | How it bounds the last chunk |
|---|---|
| Server upload `CreateUploadSession` | `totalChunks` derived from `TotalSize` (encrypted, no padding) |
| Server upload `UploadChunk` | Appends padding only on `chunkNumber == totalChunks-1` after streaming-hash update |
| Server owner download `DownloadFileChunk` | `endByte` capped at `file.SizeBytes - 1` (encrypted-stream length) |
| Server share download `DownloadShareChunk` | `endByte` capped at `sizeBytes - 1` (encrypted-stream length) |
| Browser streaming download | Server caps the range; client just decrypts whatever the server returns |
| CLI offline `decryptBundleBlob` | Loop terminates when `remaining = meta.SizeBytes` reaches 0; padding bytes (at offset `≥ meta.SizeBytes`) are never read |

No surface uses `padded_size` for chunk-range math. The padding is correctly siloed: it lives only at byte offsets `[size_bytes, padded_size)` in the S3 object and is read by exactly zero decryption paths.

---

## 3. Outcome A (uniform chunks) feasibility analysis

For Outcome A, the wire format becomes:

```
EVERY chunk: [nonce (12)][ciphertext][tag (16)]
```

No chunk-0 special case. The two-byte `[0x01][key_type]` is **redundant with the FEK envelope's existing `[0x01][key_type]` prefix** (the FEK envelope already carries the key type, and the key type is the only semantic information in the chunk-0 header).

### 3.1 Concrete changes required for Outcome A

| Surface | Change |
|---|---|
| `handlers/uploads.go CreateUploadSession` | Drop `envelopeHeaderBytes = 2`; drop `effectiveEncryptedSize := request.TotalSize - 2`; just `totalChunks := (TotalSize + encChunkSize - 1) / encChunkSize`. |
| `handlers/uploads.go UploadChunk` validation | Drop the chunk-0 special-case in `minChunkSize` / `maxChunkSize`; uniform `gcmOverhead + 1` min, `chunkSize + gcmOverhead` max. |
| `handlers/downloads.go DownloadFileChunk` | Drop `chunk0EncSize` distinction; `startByte = chunkIndex * regularEncSize`. |
| `handlers/file_shares.go DownloadShareChunk` | Same as above. |
| `client/static/js/src/files/upload.ts` | Drop `createEnvelopeHeader` per-chunk usage in upload loop; remove `if (i === 0)` branch. Drop `+ headerSize` from `calculateTotalEncryptedSize`. **Keep** `createEnvelopeHeader` for FEK envelope (the FEK envelope still has `[0x01][key_type]` — unchanged). |
| `client/static/js/src/files/streaming-download.ts` | Remove chunk-0 header-strip from both generators (owner + share). Drop ~14 lines per generator. |
| `cmd/arkfile-client/crypto_utils.go encryptChunk` / `decryptChunk` | Drop the chunk-0 branches; encryption becomes a single `[nonce][ct][tag]` path. |
| `cmd/arkfile-client/commands.go calculateTotalEncryptedSize` | Drop `+ headerSize`. |
| `cmd/arkfile-client/offline_decrypt.go decryptBundleBlob` | Simplify loop: `overhead := gcmOverhead` (constant); no per-chunk variability. |
| `crypto/chunking_constants.go` | **Keep** `EnvelopeHeaderSize()`, `Envelope` struct, `KeyTypes` map — they still describe the FEK envelope format. The two-byte FEK envelope header is unchanged. |
| `crypto/chunking-params.json` | Unchanged. The envelope/version/keyTypes fields still describe the FEK envelope. |
| Server validation of incoming chunk-0 envelope | Currently `UploadChunk` does not validate the chunk-0 envelope bytes against the session's `password_type` (it accepts any bytes). Outcome A removes this entire validation surface (was never enforced anyway). |

### 3.2 Test updates required

- `crypto/file_operations_test.go` — likely needs minor updates if any test hand-crafts a chunk-0 layout. (Phase C is rewriting these tests anyway.)
- `cmd/arkfile-client/crypto_utils_test.go TestEncryptChunk` — currently asserts chunk-0 is `headerSize` bytes longer than chunk-1. This test changes: now chunk-0 and chunk-1 are the same length when given the same plaintext.
- `client/static/js/src/__tests__/streaming-download.test.ts` `addEnvelopeHeader` — helper deleted (no longer needed to construct test inputs).
- `cmd/arkfile-client/offline_decrypt_test.go` — should still pass; the bundle format itself doesn't change at the bundle level.

### 3.3 Risk assessment for Outcome A

| Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|
| Off-by-one error in any of the 4 server/client range-math sites | LOW | Test failures caught immediately | The simplified math is harder to get wrong (one formula instead of two) |
| Cross-client compatibility breakage (CLI upload + browser download, etc.) | LOW | RED beta impact regardless (Phase C already breaks old files) | E2E + Playwright tests will catch any mismatch; CLI↔browser roundtrip is in `e2e-test.sh` Phase 8 |
| Padding invariant violated | NONE | — | All padding-related code is on the upload path and stays unchanged (padding still appended on last chunk after encrypted-stream end) |
| FEK envelope confusion | NONE | — | FEK envelope is a separate format from chunk layout; it keeps its `[0x01][key_type]` header. Only the **redundant** chunk-0 prefix is removed. |

### 3.4 Conceptual benefit of Outcome A

The chunk-0 header has been doing double duty since inception:
1. **Originally** it carried version/key-type info "in case the FEK envelope was lost or the chunks were exported separately." But Phase C makes the FEK envelope the authoritative source of this information (via FEK-envelope AAD binding `file_id || key_type`).
2. **Today** the chunk-0 prefix is never *validated* server-side and never *used* client-side beyond stripping it. The `version !== 0x01` check in `streaming-download.ts` is the only actual gate on it, and that gate fires only because the bytes are there — it has no semantic input from the rest of the system.

Once Phase C lands chunk AAD (`file_id || chunk_index || total_chunks`), the chunk-0 prefix conveys zero additional security or correctness information. Removing it eliminates a free-floating chunk-layout asymmetry that has been a continual source of off-by-one bugs (see `handlers/uploads.go` lines ~119–123 explaining a prior bug fixed by subtracting the header from `effectiveEncryptedSize`).

---

## 4. Outcome B (retain + authenticate chunk-0 header) feasibility analysis

For Outcome B, the chunk-0 header **stays** as `[0x01][key_type][nonce][ct][tag]`, but chunk-0's AAD additionally binds the two header bytes:

```
BuildChunkAAD(fileID, chunkIndex=0, totalChunks, headerBytes)
  = [len(fileID)][fileID][8B chunkIndex][8B totalChunks][2B headerBytes]
BuildChunkAAD(fileID, chunkIndex≥1, totalChunks)
  = [len(fileID)][fileID][8B chunkIndex][8B totalChunks]
```

### 4.1 Concrete changes required for Outcome B

- All range-math surfaces stay exactly as they are today.
- `BuildChunkAAD` becomes a two-shape function: chunk 0 has an extra trailing field; chunks 1+ do not.
- Every chunk-0 decrypt path must verify the header bytes match the expected format (version `0x01`, key_type matching the FEK envelope's key type) **before** passing to AES-GCM. Currently the streaming download checks `version === 0x01` but not the key-type byte against anything authoritative.
- Cross-language AAD conformance vector becomes more complex (need vectors for both chunk-0 and chunk-1+).

### 4.2 Risks specific to Outcome B

| Risk | Likelihood | Severity |
|---|---|---|
| AAD asymmetry between chunk 0 and chunks 1+ leads to off-by-one in either client | MEDIUM | Decrypt failure if Go and TS disagree |
| The chunk-0 header bytes become "load-bearing" via AAD binding but the wider system has multiple places (server validation, client validation) that could disagree on the canonical bytes | MEDIUM | Subtle decryption failures hard to debug |
| Future maintainers see two different chunk shapes and assume there must be a reason | LOW | Maintenance burden |

### 4.3 When Outcome B is right

Outcome B is the correct fallback if any of the six surfaces could not be cleanly updated for uniform chunks — e.g., if there was a hidden caller that expected the chunk-0 prefix as a marker, or if export/offline-decrypt could not be cleanly simplified. **The audit found no such caller.** Every chunk-0 prefix consumer is one of: (a) a writer that produces the prefix, (b) a reader that strips and discards it, (c) the server validation that distinguishes chunk-0 from chunks-1+ minimum sizes.

---

## 5. Recommendation: Outcome A

The audit findings argue strongly for Outcome A:

1. **Every range-math surface respects the padding invariant.** The `endByte ≤ size_bytes - 1` cap is consistent across owner download, share download, and offline decrypt. No surface uses `padded_size` for chunk-range math.

2. **The chunk-0 header is redundant.** Its `[version][key_type]` content duplicates information the FEK envelope already carries. After Phase C binds `file_id` + `key_type` into FEK-envelope AAD, the chunk-0 prefix conveys zero semantic information.

3. **Outcome A is simpler.** One range-math formula instead of two. One chunk-validation rule instead of two. One AAD shape instead of two. Simpler code is fewer places for off-by-one bugs to hide, and is the kind of "clean break" the greenfield policy in `phase-c.md` §2 was written for.

4. **Outcome A has identical Phase-C scope cost to Outcome B.** The phase already deletes the old `0x01` (no-AAD) code paths and breaks old files. The marginal cost of also dropping the chunk-0 prefix is small — about 30 lines of code removed across 6 files, plus one test helper deletion.

5. **No Phase-C-out-of-scope risk surfaced.** The audit did not turn up any caller that would need to be touched outside the Phase C scope listed in `phase-c.md` §8. Specifically, the FEK envelope format (`crypto/file_operations.go` `CreateEnvelope` / `ParseEnvelope`), the chunking-params JSON, and the export bundle JSON schema are unchanged.

**Recommendation: Outcome A — uniform chunks, drop the chunk-0 `[version][key_type]` header.**

The FEK envelope keeps its `[0x01][key_type]` header (that's a separate format and is bound into AAD via `BuildFEKEnvelopeAAD`). The chunk-0 header is the one being removed.

---

## 6. Pre-Step-1 confirmation requested

This document is the §9 Step 0 deliverable. Per the agreed workflow, Phase C does not proceed to Step 1 (Go AAD foundation) until the developer confirms the chunk-layout decision.

Please confirm one of:

- **APPROVE Outcome A** — proceed with uniform chunks. Step 1 begins.
- **APPROVE Outcome B** — proceed retaining and authenticating the chunk-0 header. (Phase C still ships; AAD construction has the chunk-0 special case.)
- **PAUSE** — flag a concern with the audit or recommendation that I should address before proceeding.
