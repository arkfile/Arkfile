# Slice D — Sharing

Driving prompt: `docs/wip/idsrp.md` §7 (sharing), §11 (metadata leakage via shares), parts of §8 (authz on share endpoints).
Master tracker: `docs/wip/review/00-plan.md` §4 Slice D.

## 0. Scope

### `idsrp.md` sections covered

- **§7 File Sharing Review** — full coverage.
- **§11 Metadata Privacy** — covered as it relates to share endpoints and share envelopes. Owner-facing metadata privacy was covered in Slice B.
- **§8 Backend Authorization** — only the share endpoints' authz, IDOR, and revocation semantics. Full endpoint table production is deferred to Slice E.
- **§14 Logging hygiene** — only for share endpoints. The general logging audit lives in Slice E.

### Deferred

- Deep CSP / Trusted-Types audit of `client/static/shared.html` -> **Slice F**. This slice flags only direct XSS sinks reachable from shared/share-list flows.
- Per-endpoint TOTP-gating table -> **Slice E**. This slice confirms the binary (anonymous share endpoints are correctly NOT TOTP-gated; owner-side share endpoints are correctly TOTP-gated).
- Server-side padding and chunk-format issues already raised against the file pipeline -> cross-ref Slice C `C-01`, `C-02`, `C-03` (the share download chunk path inherits the same byte-range arithmetic).
- Server-controlled Argon2id parameters -> cross-ref Slice B `B-19`. This slice raises the share-specific consequence (offline brute force on stolen envelopes).
- The `extractUsernameReflect` stringification hack in `logging/entity_id.go` -> primarily Slice E; touched here only because it is on the rate-limit / enumeration path for share endpoints.

### Files actually read

| File | Why |
|---|---|
| `crypto/share_kdf.go` | Argon2id share-key derivation, share envelope creation/parse, AAD construction, download-token hashing. |
| `crypto/share_kdf_test.go` | Confirms AAD binding (share_id vs file_id), wrong-password rejection, full round-trip. |
| `handlers/file_shares.go` | All share Go handlers: create, list, get-envelope, download-metadata, chunk download, revoke, page render. |
| `handlers/file_shares_test.go` | Coverage for handler boundary cases (expired/revoked/exhausted/rate-limited). |
| `handlers/share_enumeration.go` | In-memory entity-global share enumeration guard. |
| `handlers/rate_limiting.go` | Per-(share_id, entity_id) failed-attempt rate limiter; also the auth-rate-limit reuse of the same table. |
| `handlers/flood_guard.go` | 401/404 flood detection (general; not directly wired into share paths but raised at relevant boundaries). |
| `handlers/route_config.go` | Share route registrations, TOTP-gating wiring, middleware stacks. |
| `logging/entity_id.go` | EntityID HMAC construction; relevant because rate-limit keys and enumeration tracking are entity-keyed. |
| `client/static/js/src/shares/share-crypto.ts` | Browser client-side share key derivation, envelope encrypt/decrypt, AAD construction parity with Go. |
| `client/static/js/src/shares/share-creation.ts` | Owner-side share-creation flow; share-ID generation; collision retry. |
| `client/static/js/src/shares/share-access.ts` | Anonymous recipient flow; unlock UX; chunked download triggering. |
| `client/static/js/src/shares/share-list.ts` | Owner-side share-list UI (renderShareItem template). |
| `client/static/shared.html` | Anonymous recipient entry page. |

### Out-of-scope notes

- Recipient PKI / public-key directory sharing: N/A by design (see §4).
- Folder/hierarchy sharing: N/A — Arkfile is flat per-user.
- Share invitation emails / notifications: N/A — sharing is link+password.
- Multi-tenant separation: N/A — single tenant.

---

## 1. Architecture & Data-Flow Summary (for this slice)

### 1.1 Share creation (owner-side, browser/CLI)

```
[Owner browser]                                            [Server]
                                                          
Has plaintext FEK, fileId.                                 
Generates random shareID:                                  
  bytes = randomBytes(32)                                  
  shareID = base64url(bytes)   <-- 256-bit entropy         
  retry if first char is '-' or '_'                        
                                                          
share-crypto.encryptFEKForShare(fek, sharePassword,        
                               shareID, fileID, metadata): 
                                                          
  salt = randomBytes(32)            <-- 256-bit salt       
  downloadToken = randomBytes(32)   <-- 256-bit bearer     
                                                          
  envelopeJSON = {                                         
    fek: b64(fek),                                         
    download_token: b64(downloadToken),                    
    filename, size_bytes, sha256       (owner-supplied)    
  }                                                        
                                                          
  argon2Params = (server-provided)  <-- ⚠ B-19 cross-ref   
  shareKey = Argon2id(sharePassword, salt, params)         
                                                          
  AAD = utf8(shareID + fileID)      <-- naive concat       
  envelopeCT = AES-256-GCM(envelopeJSON, shareKey,         
                           nonce=random12, aad=AAD)        
                                                          
  downloadTokenHash = SHA-256(downloadToken)               
                                                          
  Wire: [nonce(12) || ciphertext || tag(16)]               
                                                          
POST /api/shares  (TOTP-gated, owner JWT)                  
  share_id, file_id, salt, encrypted_envelope,             
  download_token_hash, expires_after_minutes,              
  max_accesses                                             
                                                ──>  Validate share_id format (43-char base64url)
                                                     Check uniqueness in file_share_keys
                                                     Verify owner owns file_id
                                                     INSERT into file_share_keys
                                                     (server NEVER sees: sharePassword, FEK,
                                                      downloadToken, salt-derived key, plaintext)
                                                     Returns: share_id, share_url
```

### 1.2 Anonymous recipient unlock + download

```
[Recipient browser]                                        [Server]
                                                          
GET /shared/:id                                            
  ServeStaticHTML  shared.html                  <──   GetSharedFile (DB lookup, validates exists,
                                                       not expired; revoked status NOT checked here)
                                                          
GET /api/public/shares/:id/envelope                        
                                                ──>  ShareEnumerationMiddleware
                                                     ShareRateLimitMiddleware (per share_id+entity_id)
                                                     TimingProtectionMiddleware
                                                     Returns: share_id, file_id, salt,
                                                              encrypted_envelope, size_bytes
                                                              (no auth required)
                                                          
shareCrypto.decryptShareEnvelope(envelopeCT, password,     
                                 shareID, fileID, salt):   
                                                          
  argon2Params = (re-fetched from server)  <-- ⚠ B-19      
  shareKey = Argon2id(password, salt, params)              
  AAD = utf8(shareID + fileID)                             
  envelopeJSON = AES-GCM-decrypt(...)                      
  parse JSON -> fek, downloadToken, filename, size, sha256 
                                                          
Recipient now holds: fek, downloadToken.                   
                                                          
GET /api/public/shares/:id/metadata                        
                                                ──>  Returns: file_id, size_bytes, chunk_count,
                                                              chunk_size_bytes (rate-limited)
                                                          
For each chunk index i:                                    
  GET /api/public/shares/:id/chunks/:i                     
    X-Download-Token: <downloadToken>                      
                                                ──>  Validate token: SHA-256(decode(token))
                                                     == stored download_token_hash
                                                     (constant-time compare)
                                                     If chunk_index==0: access_count++ (race!)
                                                     Stream chunk bytes (encrypted blob slice)
                                                          
Decrypt chunks client-side with FEK, write to disk         
via SW or Blob fallback.                                   
```

### 1.3 Key hierarchy for sharing

| Material | Source | Lives | Server sees? | Used to |
|---|---|---|---|---|
| Share Password | Owner input | Recipient: typed each session | **No** | Derive Share Key |
| Salt | Owner client `randomBytes(32)` | DB plaintext (`file_share_keys.salt`) | Yes, plaintext | Argon2id input |
| Share Key | Argon2id(password, salt, params) | Client RAM only | **No** | AES-GCM-AAD on envelope |
| FEK | File creation (per-file random 256-bit) | Inside encrypted envelope; recipient RAM after unlock | **No** (only ciphertext form) | Decrypt file chunks |
| Download Token | Owner client `randomBytes(32)` | Inside encrypted envelope; recipient RAM | Only as SHA-256 hash | Authorize chunk download |
| Download Token Hash | SHA-256(downloadToken) | DB plaintext (`file_share_keys.download_token_hash`) | Yes, hash form | Server-side bearer check |
| Share ID | Client `randomBytes(32)` + base64url | DB plaintext (`file_share_keys.share_id`), in URL | Yes, plaintext | Lookup, AAD binding |
| AAD | UTF-8 `share_id + file_id` (concat) | Computed each crypto op | Yes, both parts known to server | Bind envelope to share+file |

### 1.4 Threat-model summary

- **The server cannot decrypt envelopes**: salt + ciphertext are sufficient to *attempt* offline brute force, but require Argon2id work per guess. Confidentiality of the file rests entirely on share-password strength and Argon2id memory hardness.
- **Bearer token, not capability**: anyone who learns the download token gets unlimited (modulo `max_accesses`) chunk downloads. The token is hashed at rest but used as a plaintext bearer over HTTPS.
- **Revocation is "future fetch only"**: a recipient who has unlocked the envelope and read all chunks cannot be "unlocked" — they hold the FEK forever. The product copy and `confirm()` text in `share-list.ts` say "immediately prevent anyone from accessing" — that overstates the guarantee. See **D-13**.
- **Anonymous-recipient privacy**: matches the AGENTS.md "no IP, no PII" posture. EntityID HMAC is the only persistent identifier. Caveat: anonymous EntityID rotates daily, which is also the upper bound on rate-limit memory of an attacker. See **D-11**.

---

## 2. Findings

### Finding D-01: `max_accesses` enforcement is bypassable; only checked on chunk 0

- **Severity:** High
- **Confidence:** High
- **Category:** authorization
- **Component:** `handlers/file_shares.go` :: `DownloadShareChunk`
- **Affected files / functions:** `handlers/file_shares.go:787-793, 866-886`

#### Description

`DownloadShareChunk` only enforces and increments the `access_count` / `max_accesses` check when `chunkIndex == 0`. Once any recipient has obtained a valid `X-Download-Token` and made one chunk-0 download (so the share is "started" but not necessarily completed), any number of additional `chunks/1..N` requests succeed without further accounting and without ever marking the share exhausted.

#### Evidence

```go
// handlers/file_shares.go:787-793
if chunkIndex == 0 && share.MaxAccesses.Valid &&
   int64(share.AccessCount) >= int64(share.MaxAccesses.Float64) {
    logging.WarningLogger.Printf("Chunk download attempt on exhausted share: ...")
    return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
}
```

```go
// handlers/file_shares.go:870-886
if chunkIndex == 0 {
    _, err = database.DB.Exec(`UPDATE file_share_keys
        SET access_count = access_count + 1 WHERE share_id = ?`, shareID)
    ...
}
```

There is no guard at all on `chunkIndex > 0`: those paths skip the `MaxAccesses` check (line 787 conditional on `chunkIndex == 0`) and do not increment `access_count`.

#### Attack scenario

1. Owner creates a `max_accesses=1` share intending one-shot download semantics.
2. Recipient unlocks envelope, gets `downloadToken`. Calls chunk 0 once (`access_count` -> 1).
3. Recipient (or anyone the token leaks to) now calls `chunks/1`, `chunks/2`, ... repeatedly. None of these increment `access_count`; none are blocked.
4. The "exhausted" UX is shown to the owner via `ListShares` (the share is marked inactive) but in fact unlimited additional chunk fetches continue to succeed silently. Storage egress is unbounded.

A bandwidth-amplification variant: a colluding recipient can re-download chunks 1..N indefinitely, exfiltrating gigabytes per "share" while the owner believes the share was consumed exactly once.

#### Impact

- Breaks the principal value of `max_accesses` (one-shot semantics).
- Allows arbitrary egress amplification from any valid download token, including tokens leaked from screen sharing, browser history, ad networks, etc.
- Owner UI in `share-list.ts` will mark the share as "Exhausted" (line 218) while the server is still happily serving bytes.

#### Recommendation

Apply the `MaxAccesses` check and `access_count` accounting on every chunk request, not just chunk 0. The race-y "we don't want to block in-progress downloads" comment is solvable with a *per-token-instance* download session (issue a server-side download session ID on the first chunk request and require it on subsequent chunk requests; one session = one count). Alternatively, count by downloader-EntityID within a short rolling window so that one slow legitimate downloader does not count as N.

Document explicitly in the API doc that `max_accesses` counts **download starts**, not completions, if that semantic is intentional — but right now even that is broken because chunks 1..N can be fetched without any chunk-0 increment occurring (a malicious client can skip chunk 0 entirely if they already have a token).

#### Suggested tests

- Integration test: create a `max_accesses=1` share; recipient calls chunks 1..N without chunk 0; verify the server enforces the limit (currently it does not).
- Integration test: create a `max_accesses=1` share; recipient calls chunk 0 then chunks 1..N many times; verify total downloads counted = 1, not N.
- Integration test: two concurrent recipients with the same token, both hitting chunk 0 — see also **D-02**.

#### Cross-refs

- **D-02** (race on `access_count` increment).

---

### Finding D-02: Race condition on `access_count` increment allows double-spend on `max_accesses`

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization
- **Component:** `handlers/file_shares.go` :: `DownloadShareChunk`
- **Affected files / functions:** `handlers/file_shares.go:733-735, 787-793, 870-880`

#### Description

The flow reads `share.AccessCount` (line 733-735), checks it against `MaxAccesses` (line 790), then issues a separate UPDATE `access_count = access_count + 1` (line 871). The check and the increment are not in a transaction, so two concurrent chunk-0 requests can both observe `AccessCount=0 < MaxAccesses=1`, both proceed, and both increment to 1. Effectively `max_accesses=1` becomes `max_accesses=2` under parallelism.

#### Evidence

```go
// handlers/file_shares.go:733
&share.AccessCount,
// ...
// handlers/file_shares.go:787-793 (read result evaluated)
if chunkIndex == 0 && share.MaxAccesses.Valid &&
   int64(share.AccessCount) >= int64(share.MaxAccesses.Float64) {
    return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
}
// ... no row lock ...
// handlers/file_shares.go:871-874
_, err = database.DB.Exec(`UPDATE file_share_keys
    SET access_count = access_count + 1
    WHERE share_id = ?`, shareID)
```

No `SELECT ... FOR UPDATE`, no atomic conditional UPDATE, no `CHECK` constraint clamping `access_count <= max_accesses`.

#### Attack scenario

An attacker with a valid download token fires N parallel chunk-0 requests. With `max_accesses=1` they get up to N successful downloads instead of 1, all incrementing `access_count` to N.

The rqlite consensus layer probably serializes writes at the leader, but the *reads* at the start of the handler happen at whatever replica answers, with no read-after-write barrier. The TOCTOU window between the SELECT and the UPDATE remains open.

#### Impact

- One-shot share semantics broken by trivial parallelism.
- Compounds **D-01**: even if D-01 is fixed by enforcing on every chunk, this race still lets the first N parallel chunk-0 requests succeed.

#### Recommendation

Use an atomic conditional UPDATE:

```sql
UPDATE file_share_keys
SET access_count = access_count + 1
WHERE share_id = ?
  AND (max_accesses IS NULL OR access_count < max_accesses)
```

Treat `RowsAffected() == 0` as "limit reached" and reject. This is one round-trip and is correct under concurrent writers because the WHERE clause is re-evaluated atomically. Combined with **D-01**'s fix this gives correct one-shot semantics.

#### Suggested tests

- Concurrent-goroutine integration test: 10 simultaneous chunk-0 requests on a `max_accesses=1` share; assert exactly one returns 200 and nine return 403.

---

### Finding D-03: `ListShares` GET handler performs side-effecting writes (auto-revoke)

- **Severity:** Medium
- **Confidence:** High
- **Category:** design (defense-in-depth) / authorization
- **Component:** `handlers/file_shares.go` :: `ListShares`
- **Affected files / functions:** `handlers/file_shares.go:490-518`

#### Description

`ListShares` is a GET endpoint that scans the caller's shares. While computing `is_active` for the response, it issues two side-effecting UPDATEs that set `revoked_at = CURRENT_TIMESTAMP` and `revoked_reason = 'time'` or `'exhausted'` for shares it detects as past their expiry / over their access limit. Side-effects in GET handlers violate REST semantics and create surprising behavior, e.g. a CDN, browser back/forward cache, prefetch, or test harness can trigger writes by listing.

There is also no transaction around the read+write pair; under concurrent calls, the same share can be UPDATEd twice (idempotent here, but the pattern is fragile).

#### Evidence

```go
// handlers/file_shares.go:490-505
if share.ExpiresAt.Valid && share.ExpiresAt.String != "" {
    if expiry, err := time.Parse(time.RFC3339, share.ExpiresAt.String); err == nil {
        if time.Now().After(expiry) {
            isActive = false
            if !share.RevokedAt.Valid {
                database.DB.Exec(`
                    UPDATE file_share_keys
                    SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'time'
                    WHERE share_id = ?
                `, share.ShareID)
                // ...
            }
        }
    }
}
```

The error from `database.DB.Exec(...)` is ignored.

#### Impact

- Surprising statefulness — a "view" mutates the database.
- Ignored error from `Exec` may leave the system in a half-revoked state and the operator unaware.
- A user repeatedly polling their share list incurs DB write load proportional to how many of their shares just expired.

#### Recommendation

Move expiry/exhaustion auto-revoke into either (a) a periodic background sweeper task (preferred — there is already a billing sweeper pattern in `billing/sweep.go` that this could mirror), or (b) the read-time logic computes `is_active` purely from current state without persisting it. Persistence belongs to a write operation or scheduled job.

#### Suggested tests

- Unit test: confirm `ListShares` does not write to the DB. (Currently this test would fail — that is the point.)

---

### Finding D-04: Owner-supplied `revoked_reason` leaks back to anonymous recipient

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy
- **Component:** `handlers/file_shares.go` :: `GetShareEnvelope`, `GetShareDownloadMetadata`, `DownloadShareChunk`
- **Affected files / functions:** `handlers/file_shares.go:247-253, 638-643, 746-753`; setting at `RevokeShare` `handlers/file_shares.go:299-308`

#### Description

When an owner revokes a share, they may pass a free-form `reason` in the JSON body (`RevokeShare`, `handlers/file_shares.go:299-307`). That `reason` is then included in error messages returned to the anonymous recipient on any subsequent access attempt:

```go
// handlers/file_shares.go:247-253
if share.RevokedAt != nil {
    reason := "Share has been revoked"
    if share.RevokedReason.Valid && share.RevokedReason.String != "" {
        reason += ": " + share.RevokedReason.String
    }
    return echo.NewHTTPError(http.StatusForbidden, reason)
}
```

There is no length cap, no allow-list, no sanitization. An owner can put PII ("Recipient X stalked my children"), an XSS payload (the recipient browser may or may not render it depending on context), or a tracking ping URL into `revoked_reason` and it will be served verbatim to whoever subsequently attempts the share.

#### Attack scenario

- Owner revokes share with `reason = "Caught you, John Smith of 123 Elm St"`. The recipient sees this in their error UI.
- Owner revokes with `reason = "https://attacker.example/?id=<recipient_marker>"`. Recipient sees a clickable-looking URL in their error page.
- Owner revokes with `reason = "<img src=x onerror=...>"`. Whether this fires depends on how `share-access.ts` renders the error — it uses `.textContent` for the standard "no longer valid" path (`share-access.ts:131-141`), so direct XSS is mitigated *currently*. But that depends on every downstream renderer using textContent — a fragile invariant.

#### Impact

- Privacy: an owner can leak identifying info to whoever they choose, including third parties who happened to be sent the share link.
- Defense-in-depth: an HTML-rendering view of the revoke reason elsewhere (e.g. a future admin UI, a CLI client print, a log indexing tool) creates an XSS / log-injection vector.

#### Recommendation

- Cap `revoked_reason` length to e.g. 128 chars at the API.
- Allow-list to a small set of canonical values (`manual`, `time`, `exhausted`, `policy`, `abuse`, `owner_request`, `other`) and reject free-form strings. Map `manual`/`time`/`exhausted` to localized text in the recipient UI rather than echoing server text.
- Do not leak free-form owner content to anonymous recipients on any error path.

#### Suggested tests

- Unit test: `RevokeShare` rejects `reason` longer than the cap.
- Unit test: `GetShareEnvelope` returns a generic "revoked" message regardless of stored `revoked_reason`.

---

### Finding D-05: `/shared/:id` route is missing per-share rate-limit and timing-protection middleware

- **Severity:** Medium
- **Confidence:** High
- **Category:** design / privacy
- **Component:** `handlers/route_config.go`
- **Affected files / functions:** `handlers/route_config.go:127-128` vs `handlers/route_config.go:132-139`

#### Description

The HTML share page handler `GetSharedFile` is registered at two distinct URLs with different middleware stacks:

```go
// handlers/route_config.go:128 — older entrypoint
Echo.GET("/shared/:id", ShareEnumerationMiddleware(GetSharedFile))

// handlers/route_config.go:132-139 — newer namespace
publicShareGroup := Echo.Group("/api/public/shares")
publicShareGroup.Use(ShareEnumerationMiddleware)
publicShareGroup.Use(ShareRateLimitMiddleware)
publicShareGroup.Use(TimingProtectionMiddleware)
publicShareGroup.GET("/:id", GetSharedFile)
```

The `/shared/:id` path lacks both `ShareRateLimitMiddleware` and `TimingProtectionMiddleware`. Both routes hit the same handler which performs an unconditional DB lookup at `handlers/file_shares.go:359-367`.

#### Impact

- **Rate-limit bypass**: an attacker who tripped `ShareRateLimitMiddleware` on `/api/public/shares/:id` can switch to `/shared/:id` and continue probing the same share ID without per-share rate limiting. Only the entity-global enumeration guard still fires (and only on 404, not on 200 — so probing valid shares costs nothing).
- **Timing oracle**: without `TimingProtectionMiddleware`, response time differs between "share exists in DB" and "share not found". An attacker can race-fingerprint via the timing diff even when the response body is identical (both serve a 200 with the same static HTML for the happy path).

#### Recommendation

- Either remove the `/shared/:id` route entirely and have the client always hit `/api/public/shares/:id` for the page (this is what `share-access.ts` does at `:124`), or
- Apply the same three middlewares to `/shared/:id`. The simplest fix is to declare `/shared/:id` inside `publicShareGroup` as well, or build a small middleware-list constant and apply it consistently.

#### Suggested tests

- Routing test: GET `/shared/:id` returns 429 after the per-share failure threshold is reached on the same share ID.
- Timing test: GET `/shared/:id` for an existing vs. non-existent share, measure that timing-protection equalizes them.

---

### Finding D-06: Race + read-then-write on per-share rate-limit failed_count

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization
- **Component:** `handlers/rate_limiting.go` :: `recordFailedAttempt`, `recordAuthFailedAttempt`
- **Affected files / functions:** `handlers/rate_limiting.go:94-146, 546-600`

#### Description

`recordFailedAttempt` reads `failed_count` then writes `failed_count = newFailureCount` with no transaction:

```go
// handlers/rate_limiting.go:97-100
err := database.DB.QueryRow(`
    SELECT failed_count FROM share_access_attempts
    WHERE share_id = ? AND entity_id = ?
`, ...).Scan(&currentFailureCount)
// ...
// handlers/rate_limiting.go:125-136
newFailureCount := currentFailureCount + 1
// ...
_, err = database.DB.Exec(`UPDATE share_access_attempts
    SET failed_count = ?, ... WHERE share_id = ? AND entity_id = ?`,
    newFailureCount, ...)
```

Two concurrent failed attempts can both read `failed_count=N` and both write `failed_count=N+1`, undercounting failures by one. Repeated under parallelism this gives an attacker a multiplicative discount on the rate-limit budget.

#### Impact

- Slower, weaker progressive rate limiting under concurrent attack — favors the attacker.
- Same pattern exists in `recordAuthFailedAttempt` for login/register/TOTP rate limits (`handlers/rate_limiting.go:546-600`). Slice A's TOTP findings should cross-reference this; for this slice the share-bruteforce angle is in scope.

#### Recommendation

Use an atomic conditional UPSERT or `UPDATE ... SET failed_count = failed_count + 1` with a server-side computed `next_allowed_attempt = CURRENT_TIMESTAMP + <penalty(failed_count)>` — but rqlite/SQLite cannot compute the penalty inline because it is a function of the post-increment failure count. The two-step approach can be made safe by wrapping in a transaction or by relying on the `RowsAffected()` semantics with an `INSERT ... ON CONFLICT DO UPDATE SET failed_count = failed_count + 1`, then reading back the new count in the same transaction.

A simpler form: a single atomic increment, followed by a SELECT inside the same transaction to compute the penalty.

#### Suggested tests

- Concurrency test: 20 parallel `recordFailedAttempt` calls — assert final `failed_count == 20`.

---

### Finding D-07: `share_access_attempts` table grows unbounded; no DB-side cleanup

- **Severity:** Low
- **Confidence:** High
- **Category:** operational
- **Component:** `handlers/rate_limiting.go`
- **Affected files / functions:** `handlers/rate_limiting.go` (whole file); also `handlers/share_enumeration.go` for the in-memory analog (the in-memory analog *does* clean up)

#### Description

Every (share_id, entity_id) pair that ever fails an access attempt produces a row in `share_access_attempts` that is never deleted. Authentication endpoints (login, register, totp_verify, totp_auth) reuse the same table with synthetic share_ids of the form `"auth_<endpointType>_<entityID>"` (line 500), so each unique anonymous EntityID also leaves a permanent row per endpoint it touched.

There is no reaping job in this slice. (`handlers/share_enumeration.go` does have an in-memory `cleanupLoop`, but that is the entity-global enumeration guard, not the persistent rate-limit table.)

#### Impact

- DB grows linearly with unique (share_id, entity_id) pairs forever.
- EntityIDs rotate daily (see **D-11**) so for an active deployment the row count grows by ~(daily_unique_entities × shares_they_probed) per day.
- Eventually this will affect rqlite snapshot size and query performance on the auth-rate-limit synthetic-share_id rows.

#### Recommendation

Add a periodic sweeper (mirroring `billing/sweep.go`) that deletes rows where `last_failed_attempt < now() - retention_period` and `next_allowed_attempt < now()`. Reasonable retention: 30 days, configurable.

#### Suggested tests

- Sweeper unit test with frozen clock.

---

### Finding D-08: Share rate-limit reuse table schema confusion (auth rate limits stored as fake share IDs)

- **Severity:** Low
- **Confidence:** High
- **Category:** design / code-clarity
- **Component:** `handlers/rate_limiting.go` :: `getOrCreateAuthRateLimitEntry`, `recordAuthFailedAttempt`
- **Affected files / functions:** `handlers/rate_limiting.go:494-543, 545-600`

#### Description

`getOrCreateAuthRateLimitEntry` synthesizes a `share_id = "auth_" + endpointType + "_" + entityID` and writes it into the `share_access_attempts.share_id` column. The WHERE clause then matches `share_id = "auth_login_<E>" AND entity_id = <E>` — the entity_id is encoded twice. The Scan also maps `share_id` -> `entry.EndpointType` (a typed-string field), so the field is misleadingly named.

This is functional but fragile, and it pollutes the share-rate-limit table with auth-rate-limit rows that cannot be told apart from real shares without prefix inspection. It also means the **share enumeration guard counting unique share IDs sees these synthetic auth entries** if the same entity hits multiple auth endpoints — but it doesn't because the guard is keyed on share-handler 404s only, not auth failures. Still, the design is brittle.

#### Recommendation

Move auth rate limits to a separate table (`auth_attempts` with columns `endpoint_type`, `entity_id`, `failed_count`, `last_failed_attempt`, `next_allowed_attempt`). The schema is simpler and the cross-cuts disappear.

#### Cross-refs

- Slice A — the same pattern is what the OPAQUE / TOTP / login rate-limit code uses. Slice A may already have flagged this. (This Slice D notes it because it directly bleeds into share-handler analysis.)

---

### Finding D-09: Origin-header trust in share URL construction allows owner-side phishing/self-XSS amplification

- **Severity:** Medium
- **Confidence:** Medium
- **Category:** design / privacy
- **Component:** `handlers/file_shares.go` :: `CreateFileShare`, `ListShares`
- **Affected files / functions:** `handlers/file_shares.go:135-156, 471-483`

#### Description

When `cfg.Server.BaseURL` is unset, `CreateFileShare` and `ListShares` fall back to constructing share URLs from `c.Request().Header.Get("Origin")`, and ultimately from `c.Request().Host`:

```go
// handlers/file_shares.go:140-156
if cfg.Server.BaseURL != "" {
    baseURL = cfg.Server.BaseURL
} else {
    origin := c.Request().Header.Get("Origin")
    if origin != "" {
        baseURL = origin
    } else {
        scheme := "https"
        if c.Echo().Debug && c.Request().TLS == nil {
            scheme = "http"
        }
        baseURL = scheme + "://" + c.Request().Host
    }
}
shareURL := baseURL + "/shared/" + request.ShareID
```

Both `Origin` and `Host` are attacker-controllable when the request comes from a script the attacker placed in the user's browser (XHR can set arbitrary `Host`/`Origin`-equivalent in some edge cases; `Host` is controlled by an upstream proxy and may not be validated by Caddy).

#### Attack scenario

If a deployment runs without `BASE_URL` set (the documented production path uses `BASE_URL`, but local/test deployments do not — see comment at line 144 "Fallback for local/dev deployments where BASE_URL is not configured"), an attacker who induces the legitimate user to issue a share creation with a crafted `Origin` header receives a `share_url` rooted at `https://attacker.example/shared/<id>`. The owner copies it into their UI and may share it externally believing it's the real URL.

For the request to come with an attacker-chosen `Origin`, the attacker generally needs script execution in the owner's browser already (which is a higher bar than the finding requires). However, in self-XSS or content-injection scenarios that don't yet have full DOM control, this is a useful amplification.

#### Impact

- Phishing primitive in non-production deployments that omit `BASE_URL`.
- Test/dev deployments and self-hosted users who do not set `BASE_URL` are exposed.

#### Recommendation

- Make `BASE_URL` mandatory and fail closed at startup if it is missing. The fallback chain (`Origin` -> `Host` -> "https") is a footgun for an app whose share URLs are user-visible and shareable.
- If a fallback must remain for dev convenience, gate it behind `Echo.Debug == true` and log a loud warning at startup.

#### Suggested tests

- Startup test: refuse to boot in non-debug mode when `BASE_URL` is empty.
- Handler test: with `BASE_URL=""` and `Echo.Debug=false`, `CreateFileShare` returns 500 rather than minting an attacker-controllable URL.

---

### Finding D-10: Share security model = pure-offline brute force on stolen envelope (cross-ref B-19)

- **Severity:** High
- **Confidence:** High
- **Category:** design / cryptographic
- **Component:** `crypto/share_kdf.go` + `client/static/js/src/shares/share-crypto.ts`
- **Affected files / functions:** `crypto/share_kdf.go:67-77`, `share-crypto.ts:176-217, 300-308`

#### Description

The share-envelope security model rests entirely on Argon2id memory-hardness applied to the share password. Anyone who obtains:
- the encrypted envelope blob (`encrypted_fek` from the DB, retrievable by anonymous GET on `/api/public/shares/:id/envelope` *before* triggering any rate limit, since the first request is a 200), and
- the salt (returned in the same response), and
- the Argon2id parameters (fetched from `/api/config/argon2`, which is a public endpoint per `handlers/route_config.go:54`),

can perform offline brute force without ever touching the server again. The server cannot detect, throttle, or revoke offline brute force. The only protection is the Argon2id work factor and the share-password entropy.

Compounding this:

- **The Argon2id parameters are fetched from the server unauthenticated and unauthenticated-to-the-share** (cross-ref Slice B `B-19`). A malicious or compromised server (or one whose `argon2id-params.json` was tampered with at deploy time) can serve weak params at create time, recipient time, or both. The salt is stored but the *params used* are not. A recipient on a compromised network or a maliciously-modified frontend cannot detect param downgrade.

- **Server-stored salt + ciphertext + public params is sufficient for the server operator (or anyone with read access to `file_share_keys`) to attack every share offline at leisure**. The threat model in `idsrp.md` §2 includes "Malicious or compromised server operator" — for sharing, this adversary can mount unlimited offline brute force on every share that has ever existed.

#### Evidence

```go
// crypto/share_kdf.go:67-77 — server-side derivation reads params from the same global
key := argon2.IDKey([]byte(password), salt,
    ShareKDFParams.Iterations,
    ShareKDFParams.Memory,
    ShareKDFParams.Parallelism,
    ShareKDFParams.KeyLength,
)
```

```ts
// share-crypto.ts:176, 301 — params fetched from server, no integrity binding
const argon2Params = await getArgon2Params();
// ...
const keyDerivation = await deriveKeyArgon2id({
    password: sharePassword, salt, params: argon2Params,
});
```

```
GET /api/config/argon2  -- public endpoint (route_config.go:54)
```

#### Attack scenario

1. Server operator (or someone with DB read) takes a backup of `file_share_keys`. They now have `(share_id, salt, encrypted_envelope)` for every share.
2. They run an Argon2id-accelerated GPU cluster against likely share-password dictionaries. For every share whose password is in their wordlist, they recover the share key, decrypt the envelope, extract the FEK + download token + filename + sha256.
3. They use the download token (or replay it as an anonymous recipient) to fetch and decrypt every chunk of the corresponding file.
4. This is silent — the share owner never sees an `access_count` increment because the operator can bypass the access-count check (see **D-01** / **D-02**) and there is no logging visible to the owner.

A weaker variant: an attacker who is not the operator but who knows or guesses share IDs probes `/api/public/shares/:id/envelope` once per share to retrieve `(salt, encrypted_envelope)`, then attacks offline. The per-share rate limiter cannot help once the envelope is downloaded.

#### Impact

- For shares with weak passwords (e.g. user-chosen "vacation2025!"), recovery is fast on modern hardware even with strong Argon2id.
- For shares with strong passwords (per `crypto/password-requirements.json`), recovery cost rises but is still finite and parallelizable.
- The product claim "Share password is never sent to the server" (true) is **not equivalent to** "the server cannot recover share contents" (false, in the malicious-operator threat model).

#### Recommendation

In priority order:

1. **Document the threat model honestly**: in `docs/security.md` and user-facing share creation UX, state that a malicious server operator can mount offline brute force on shares, and that share password strength is the only defense. This matches AGENTS.md "honesty and transparency".
2. **Bind Argon2id parameters into the envelope's AAD**: include the params (memory, iterations, parallelism, keylen) in the AAD or store them alongside the salt in `file_share_keys`. This prevents silent parameter downgrade — a recipient using mismatched params will fail decryption rather than succeed at an attacker-chosen weak point.
3. **Consider an integrity-bound `/api/config/argon2` response**: signed by a server long-term key whose public half is bundled with the frontend. This makes server-side parameter manipulation noisy. (Heavier lift; deferrable.)
4. **Raise the minimum share-password entropy floor in `crypto/password-requirements.json`** (Slice B item) — share passwords get the same treatment as account passwords, but they are the *only* line of defense, so the floor should be higher.

#### Cross-refs

- **B-01 / B-03 / B-19** (server-controlled crypto params).
- **B-06** (server-applied padding cross-cuts file-side).
- **A-?** (offline cracking resistance question 1 in `idsrp.md` §19 — this finding feeds the answer for shares specifically).

#### Suggested tests

- Negative test: tampered Argon2id params on the server cause envelope decryption to fail at the recipient (after the recommended AAD binding is applied).

---

### Finding D-11: Anonymous EntityID rotates daily; rate-limit budget effectively resets daily and is trivially multipliable by UA cycling

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization / design
- **Component:** `logging/entity_id.go` + `handlers/share_enumeration.go` + `handlers/rate_limiting.go`
- **Affected files / functions:** `logging/entity_id.go:78-102, 112-114`; `handlers/share_enumeration.go:18-28`; `handlers/rate_limiting.go:25-43`

#### Description

The anonymous EntityID is `HMAC(daily_key, "anon:" + IP + "|" + UserAgent + "|" + AcceptLanguage)`, where `daily_key` rotates every UTC day (`logging/entity_id.go:112-114`). All rate-limit state and enumeration tracking is keyed on this EntityID.

This has two consequences for shares:

1. **Daily reset**: At UTC midnight, every anonymous attacker gets a fresh EntityID and their share rate-limit / enumeration penalty starts at zero. With the per-share penalty cap of 30 minutes (`handlers/rate_limiting.go:42`) and the enumeration block cap of 1 hour (`handlers/share_enumeration.go:27`), a determined attacker can simply pace themselves to one offense per day and never accumulate persistent penalty.

2. **UA / Accept-Language cycling**: Different `User-Agent` or `Accept-Language` strings yield different EntityIDs for the *same* IP. A scraper that cycles 100 UA strings has 100x the rate-limit budget against any given share password.

The enumeration window is 10 minutes and 32 unique 404s in that window triggers a 1-hour block — but the attacker can use 32 UA strings to get 32 *different* EntityIDs and 32 separate counters, defeating that bound.

#### Evidence

```go
// logging/entity_id.go:88-95
} else if input.IP != nil {
    mac.Write([]byte("anon:"))
    mac.Write([]byte(input.IP.String()))
    mac.Write([]byte("|"))
    mac.Write([]byte(input.UserAgent))
    mac.Write([]byte("|"))
    mac.Write([]byte(input.AcceptLanguage))
}
```

```go
// logging/entity_id.go:112-114
func (e *EntityIDService) GetCurrentTimeWindow() string {
    return time.Now().UTC().Format("2006-01-02")
}
```

#### Impact

- A network attacker probing share passwords or share IDs has a low cost per attempt and effectively no long-term penalty accumulation.
- The progressive penalty design in `handlers/rate_limiting.go` is mostly cosmetic against a competent adversary.

#### Recommendation

- **Drop UA and Accept-Language from anonymous EntityID construction**: use IP + a coarse cohort (subnet /24 for IPv4, /48 for IPv6). UA-based disambiguation is undermined by trivial spoofing and provides no real benefit. Better: peg rate limits to (IP-or-/64-prefix) only, and accept some collateral damage for NAT.
- Or: keep the composite construction but additionally maintain a coarser per-IP counter so UA cycling cannot evade.
- **Lengthen the daily-rotation window** for rate-limit purposes only: keep daily rotation for log-friendliness, but persist rate-limit counters under a rolling 7-day key derivation so cross-day attacks are still throttled.

These are operationally heavy changes; at minimum, **document the bypass** in `docs/security.md` so users understand the actual rate-limit budget for anonymous adversaries.

#### Cross-refs

- **D-13** (revocation semantics).

#### Suggested tests

- Test: a scraper using 64 distinct UA strings against the same share is allowed 64 × 3 = 192 wrong-password attempts before hitting any per-share penalty, instead of the expected 3.

---

### Finding D-12: Share envelope has no per-envelope versioning or KDF parameter binding

- **Severity:** Medium
- **Confidence:** High
- **Category:** cryptographic / design
- **Component:** `crypto/share_kdf.go` :: `ShareEnvelope`, `CreateAAD`
- **Affected files / functions:** `crypto/share_kdf.go:108-114, 128-143, 160-165`; `share-crypto.ts:91-97, 186, 311`

#### Description

The share envelope JSON has fields `fek`, `download_token`, `filename`, `size_bytes`, `sha256`. It does **not** include:

- A version byte / format identifier — so the format cannot evolve without breaking deployed shares.
- The Argon2id parameters used to derive the key (memory, iterations, parallelism, output length).
- The AEAD algorithm identifier.
- The AAD construction scheme.

The AAD itself is the raw byte concatenation `shareID + fileID` with no separator and no length-prefixing.

Two consequences:

1. **Parameter downgrade is invisible**: re-use of the salt with a different set of Argon2id parameters at decrypt time fails generically as a "wrong password" — there is no way for the recipient to detect that the server (or a tampered frontend bundle) has lowered the work factor. See **D-10**.

2. **AAD ambiguity is mitigated only by fixed-length share IDs**: `isValidShareID` (`handlers/file_shares.go:962`) requires exactly 43 chars, so the concatenation `share_id||file_id` is unambiguous in *practice* — but the construction is a footgun. If `file_id` ever changes format (e.g. variable length, or a UUID), or if `share_id` validation is relaxed (e.g. to allow legacy formats), an AAD collision becomes possible: `share=AAA, file=BBB` vs `share=AAAB, file=BB` produce identical AAD strings.

#### Evidence

```go
// crypto/share_kdf.go:160-165
func CreateAAD(shareID, fileID string) []byte {
    return []byte(shareID + fileID)
}
```

```ts
// share-crypto.ts:186
const aad = new TextEncoder().encode(shareId + fileId);
```

```go
// crypto/share_kdf.go:108-114 — no version field
type ShareEnvelope struct {
    FEK           string `json:"fek"`
    DownloadToken string `json:"download_token"`
    Filename      string `json:"filename,omitempty"`
    SizeBytes     int64  `json:"size_bytes,omitempty"`
    SHA256        string `json:"sha256,omitempty"`
}
```

#### Recommendation

- Add a `v` field to the JSON envelope (e.g. `"v": 1`) and reject unknown versions on parse.
- Construct AAD with length-prefixed or delimiter-protected components, e.g. `len32(share_id_bytes) || share_id_bytes || len32(file_id_bytes) || file_id_bytes`. Apply on both Go and TS sides; covered by an existing-format compat test that confirms current shares still decrypt.
- Include Argon2id params either inside the envelope JSON (so re-fetching from server is unnecessary) or in the AAD (so silent downgrade fails decryption). The former is simpler — store the params alongside the salt and treat the server-fetched params as a *hint* validated against the envelope.

#### Suggested tests

- Negative test: AAD constructed with `share=AB, file=C` cannot decrypt envelope encrypted with `share=A, file=BC`. (Currently it can, if the IDs were variable-length — happens not to be exploitable today because of the 43-char constraint.)
- Negative test: envelope encrypted with `Argon2id m=128MB, t=3` cannot be decrypted with `Argon2id m=64KB, t=1` even if same salt and password.

#### Cross-refs

- **D-10** (offline brute force enabled by lack of param binding).
- **B-02 / B-05 / B-08** (related no-AAD findings against file/chunk crypto in Slice B).

---

### Finding D-13: Revocation UI overstates the guarantee ("immediately prevent anyone from accessing")

- **Severity:** Medium
- **Confidence:** High
- **Category:** design / privacy / honesty
- **Component:** `client/static/js/src/shares/share-list.ts`
- **Affected files / functions:** `share-list.ts:377-381`

#### Description

The `confirm()` text shown to the owner when revoking a share says:

> "Are you sure you want to revoke this share?
>
> This will immediately prevent anyone from accessing the file using this share link.
>
> This action cannot be undone."

This is materially false. A recipient who has already unlocked the envelope possesses:

- The FEK in plaintext (or in their browser RAM).
- The download token.
- The decrypted file metadata.

Revocation prevents **future** server-side chunk fetches under that share — but if the recipient has already downloaded all chunks, they hold the plaintext file forever. There is no cryptographic guarantee about already-fetched material because file keys are not rotated on revoke (which would require re-uploading the file, which the design correctly avoids).

This is the standard limitation of password-derived share envelopes, but the UX text claims otherwise.

#### Recommendation

Change the `confirm()` text to something honest, e.g.:

> "Revoke this share?
>
> This stops the server from serving file chunks under this share link from now on. People who already downloaded the file or already obtained the download key keep what they have — revocation cannot recover files that have already left the server.
>
> This action cannot be undone."

Apply the same correction in any documentation that describes revocation.

#### Cross-refs

- **D-04** (revocation reason leakage).

#### Suggested tests

- Documentation test: `docs/security.md` correctly distinguishes "future fetch revocation" from "already-downloaded key revocation".

---

### Finding D-14: Self-XSS via Origin-controlled `share_url` rendered into `innerHTML`

- **Severity:** Low
- **Confidence:** Medium
- **Category:** frontend
- **Component:** `client/static/js/src/shares/share-list.ts`
- **Affected files / functions:** `share-list.ts:255-263` (template), `share-list.ts:259` (value), `share-list.ts:189` (innerHTML sink)

#### Description

`renderShareItem` builds an HTML template literal that includes `share.share_url` as an attribute value:

```ts
// share-list.ts:255-263
<input
    type="text"
    readonly
    value="${share.share_url}"
    class="share-url-input"
    id="url-${share.share_id}"
    onclick="this.select()"
/>
```

`share.share_url` is computed by the server (`handlers/file_shares.go:471-483`) from `cfg.Server.BaseURL` if set, else from `Origin` header, else from `Host`. There is no HTML-attribute escaping at the rendering point.

If a deployment runs without `BASE_URL` and a request reaches `ListShares` with `Origin: ">malicious</input><script>...</script>`, the script would land in the owner's own DOM. This is **self-XSS** (the attacker must already control the request's `Origin` header, which usually requires script execution in the owner's browser).

Additionally, `share.filename_local` is interpolated at line 214-216 → 247 via `${filenameDisplay}` directly into the HTML template. `filename_local` is the recipient-decrypted-style metadata, but in `share-list.ts` it is the *owner's own* filename. Owner-controlled, viewed by the owner — self-XSS at worst.

#### Evidence

```ts
// share-list.ts:189
this.container.innerHTML = html;

// share-list.ts:247
<h3>${filenameDisplay}${inactiveBadge}</h3>

// share-list.ts:259
value="${share.share_url}"
```

No `escapeHtml(...)` calls anywhere in the render path.

#### Impact

- Limited (self-XSS), but a defense-in-depth gap and a template-literal habit that becomes load-bearing the moment any of these fields ever flows from another user (e.g. a future "shares received from others" view).

#### Recommendation

- Add a small `escapeHtml()` helper and use it consistently for every interpolated field in template literals across the share-list rendering. Better: switch to DOM-builder APIs (`document.createElement` + `.textContent`) which are XSS-safe by construction.
- Add a CSP `script-src 'self'` policy at the Caddy layer (Slice F) so injected inline scripts fail to execute regardless.

#### Cross-refs

- **D-09** (Origin-header trust is the upstream of the malicious `share_url`).
- **Slice F** — full CSP review.

#### Suggested tests

- Render test: `share.filename_local = '<img src=x onerror=...>'` does not execute when rendered.

---

### Finding D-15: Plaintext `file_id` and EntityID logged on every anonymous share access

- **Severity:** Low
- **Confidence:** High
- **Category:** privacy
- **Component:** `handlers/file_shares.go`
- **Affected files / functions:** `handlers/file_shares.go:282, 409, 681, 908`

#### Description

Several share handlers `InfoLogger.Printf` with `share_id[:8]`, the *full* `file_id`, and the EntityID:

```go
// handlers/file_shares.go:282
logging.InfoLogger.Printf("Share envelope accessed: share_id=%s..., file=%s, entity_id=%s",
    shareID[:8], share.FileID, entityID)

// handlers/file_shares.go:681
logging.InfoLogger.Printf("Share chunk info accessed: share_id=%s..., file=%s, entity_id=%s",
    shareID[:8], share.FileID, entityID)

// handlers/file_shares.go:908
logging.InfoLogger.Printf("Share chunk download: share_id=%s..., chunk=%d/%d, entity_id=%s",
    shareID[:8], chunkIndex, chunkCount, entityID)
```

Per-access logs joined on `(file_id, entity_id)` reconstruct the **access graph** of every share by every anonymous recipient. A log-reader (whether legitimate operator or insider with log access) can:

- See which anonymous recipients (by stable-per-day EntityID) accessed which file.
- Combine with the owner-side `database.LogUserAction(username, "created_share", ...)` (line 160) to map files to owners to access patterns.
- File IDs themselves are server-internal but are joinable across logs — they are a stable identifier for the underlying object.

EntityID is HMAC-protected and rotates daily, which is the privacy-preserving choice, but the *combination* of `entity_id + file_id` still allows access-pattern analysis within a 24-hour window for any individual file.

The `share_id[:8]` truncation is good. The `file_id` should also be truncated or replaced with an HMAC-derived per-log identifier.

#### Recommendation

- Replace `share.FileID` in InfoLogger output with a short prefix or a per-log HMAC: `logging.HashID(file_id, "share_access_log")`.
- Decide deliberately whether per-access logs are needed at INFO level at all. For an anti-abuse signal, aggregate counters (per-share total downloads per day) are usually sufficient. Per-access logs are a metadata-leak side channel.

#### Cross-refs

- **C-15** (Slice C raised plaintext-username + file_id in InfoLogger on owner-side downloads). This is the share-side analog.

#### Suggested tests

- Audit log scrape test: confirm INFO-level log entries for anonymous share access do not contain full file_id or owner username.

---

### Finding D-16: No rate limit on the chunk-download endpoint beyond the per-share failed-token limiter

- **Severity:** Low
- **Confidence:** High
- **Category:** authorization / operational
- **Component:** `handlers/file_shares.go` :: `DownloadShareChunk` + middleware stack
- **Affected files / functions:** `handlers/file_shares.go:691-913`; `handlers/route_config.go:132-139`

#### Description

`DownloadShareChunk` is wired through `ShareRateLimitMiddleware`, but that middleware **only blocks when a prior failed attempt is in `share_access_attempts`**. With a valid `X-Download-Token`, every chunk request hits the storage backend with no rate limiting at all. There is no per-IP egress cap, no per-share bandwidth cap, no per-token request-rate cap.

#### Impact

- A recipient who has unlocked a share can hammer the storage backend at maximum line rate, amplified by **D-01** (chunks 1..N never increment `access_count`).
- Storage egress costs (especially to paid backends like Wasabi/S3) are unbounded per share.
- DoS against the rqlite leader is plausible at high concurrency.

#### Recommendation

- Add a per-`(share_id, entity_id)` request-rate cap (e.g. token-bucket: 10 chunk requests/second sustained, burst of 50). This is independent of the failed-attempts limiter.
- Optionally a per-share total-bytes-served cap that the owner can set (separate from `max_accesses` count of starts).

#### Cross-refs

- **D-01** (`max_accesses` bypass on chunks 1..N).

#### Suggested tests

- Concurrent-load test: 1000 chunk requests/second against a single share with a valid token; assert >95% throttled, no storage-backend DoS.

---

### Finding D-17: Download-token comparison decode failures leak format-vs-mismatch oracle

- **Severity:** Low
- **Confidence:** Medium
- **Category:** cryptographic / design
- **Component:** `handlers/file_shares.go` :: `hashDownloadToken`, `constantTimeCompare`
- **Affected files / functions:** `handlers/file_shares.go:762-785, 927-955`

#### Description

`DownloadShareChunk` validates the token in two steps:

1. `hashDownloadToken(downloadToken)` — base64-decodes the supplied token, returns an error if decode fails (line 932).
2. `constantTimeCompare(computedHash, share.DownloadTokenHash)` — base64-decodes both hashes; if either decode fails, returns false (`constantTimeCompare:949-951`).

For an invalid base64 token, step 1 returns an error and a different code path (`logging.WarningLogger.Printf("Invalid download token format: ...")` line 764) than for a valid-format-but-wrong token (`logging.WarningLogger.Printf("Invalid download token: ...")` line 770). The wire response is the same 403, but:

- The log line differs in wording.
- The two paths execute slightly different amounts of work and may be timing-distinguishable (step 1 is a quick decode + SHA-256; step 2 is decode + decode + constant-time compare).

The probability that a base64-mangled token is detectable from a wire-timing oracle is small but non-zero, and the response leaks via log analysis if a log-aware attacker is present.

#### Recommendation

- Treat both failure modes identically: a base64-decode failure in step 1 should also feed `recordFailedAttempt` and emit the same `EventInvalidDownloadToken` log line. Currently only the constant-time-compare failure does (line 781).
- Use one fixed-time path: decode-or-zero-fill, compute the hash, compare in constant time, always return the same 403 regardless of which step "logically" failed.

#### Suggested tests

- Wire-timing test: invalid-base64 token and valid-base64-wrong-hash token return within indistinguishable timing windows.

---

### Finding D-18: Share enumeration guard is in-memory only; no multi-instance coherence

- **Severity:** Low
- **Confidence:** High
- **Category:** operational
- **Component:** `handlers/share_enumeration.go`
- **Affected files / functions:** `handlers/share_enumeration.go:39-52`

#### Description

`shareEnumerationGuard.trackers` is a process-local `map[string]*enumerationTracker`. If Arkfile is ever deployed behind a load balancer with N app instances, an attacker who balances probes across instances effectively gets N × budget before the enumeration guard fires. Same for the `floodGuardService` in `handlers/flood_guard.go`.

The current deployment (`systemd/arkfile.service`) appears single-instance, so this is not yet exploitable. But the design has no path to horizontal scale without either (a) shared state (e.g. rqlite-backed) or (b) sticky entity-routing at the LB.

#### Recommendation

- Either document that Arkfile is single-instance-only for these guards to be effective, or
- Move enumeration tracking to the same `share_access_attempts`-style DB table that already backs the per-share-ID rate limiter (with the cleanup sweeper from **D-07** applied).

#### Cross-refs

- **D-07** (DB-backed share_access_attempts hygiene).

#### Suggested tests

- Multi-instance integration test (if/when applicable): probe Arkfile across two instances and confirm the enumeration guard fires at the same threshold globally.

---

### Finding D-19: Anonymous EntityID for share access bypassable to fresh state by attacker without persistent identity

- **Severity:** Low
- **Confidence:** Medium
- **Category:** design
- **Component:** `logging/entity_id.go`
- **Affected files / functions:** `logging/entity_id.go:88-95, 312-320`

#### Description

For *anonymous* requests (the entire share-recipient flow), the EntityID is `HMAC(daily_key, "anon:" + IP + "|" + UserAgent + "|" + AcceptLanguage)`. There is no cookie, no client-side persistent identifier — an attacker can switch IPs (VPN/Tor/residential proxy network), UA, or Accept-Language to mint a fresh EntityID at will.

This is the privacy-preserving choice and aligns with AGENTS.md "no IP, no PII". But it means **all share-access rate limiting and enumeration tracking can be defeated by a sufficiently funded attacker**. The Tor adversary, residential-proxy adversary, and CG-NAT-mobile adversary all defeat these controls trivially.

#### Impact

- Rate limits are speed bumps, not actual defenses, against motivated adversaries.
- The actual security floor for shares is the share password's Argon2id-protected entropy (**D-10**).

#### Recommendation

- **Document this as a deliberate design decision**, not as a security guarantee, in `docs/security.md` and the share creation UX. AGENTS.md "honesty and transparency" applies.
- Continue tightening the share-password strength floor (`crypto/password-requirements.json` for share class) since that is the actual defense.

#### Cross-refs

- **D-10** (offline brute force is the actual threat model).
- **D-11** (daily rotation + UA cycling).

---

### Finding D-20: `revoked_at` not checked in `GetSharedFile` HTML-page path

- **Severity:** Low
- **Confidence:** High
- **Category:** design / UX
- **Component:** `handlers/file_shares.go` :: `GetSharedFile`
- **Affected files / functions:** `handlers/file_shares.go:349-413`

#### Description

`GetSharedFile` (the HTML-page handler) checks `expires_at` (line 390) but **not** `revoked_at`. A revoked share still returns 200 with the static `shared.html`. The page then fetches `/api/public/shares/:id/envelope`, which **does** check `revoked_at` and returns 403, after which `share-access.ts` shows "This share is no longer valid" (line 132).

Functionally this is fine — the recipient eventually sees the right message — but two issues:

1. **Wasted round-trip**: the page loads, runs JS, fires a second request to learn the share is dead. A direct 410/404 at the page level would be faster.
2. **Confused state for cached pages**: a recipient who loaded `/shared/:id` before revocation and revisits after revocation will see the password form rendered, type their password, and get a wrong-feeling error.

#### Recommendation

Add the `revoked_at` check to `GetSharedFile`, mirroring `GetShareEnvelope`. Return 403 with a redirect or static "Share revoked" page.

#### Suggested tests

- Handler test: revoked share returns 403 from `/shared/:id`, not 200.

---

### Finding D-21: `GetShareDownloadMetadata` returns `chunk_count` and `chunk_size_bytes` without requiring the download token

- **Severity:** Low
- **Confidence:** High
- **Category:** privacy / design
- **Component:** `handlers/file_shares.go` :: `GetShareDownloadMetadata`
- **Affected files / functions:** `handlers/file_shares.go:571-689`

#### Description

`/api/public/shares/:id/metadata` returns `file_id`, `size_bytes`, `chunk_count`, `chunk_size_bytes` to any anonymous caller — no download token, no share password verification, only rate limiting.

This means anyone who knows or guesses a valid share ID learns:

- That the file exists.
- Its exact size (already leaked via the envelope endpoint too).
- The chunking parameters and total chunk count.

Combined with `GetShareEnvelope`, an anonymous prober gathers `(salt, encrypted_envelope, size_bytes, chunk_count)` for offline analysis without ever attempting the password. This feeds **D-10**.

#### Recommendation

- Optional but ideal: require the X-Download-Token on `/metadata` as well as on `/chunks/:i`. Recipients only need metadata after they have unlocked the envelope and obtained the token, so this is API-compatible.
- Or: include the chunk metadata in the encrypted envelope itself and remove the `/metadata` endpoint entirely. Less server load and tighter information control.

#### Suggested tests

- Negative test: `/api/public/shares/:id/metadata` without `X-Download-Token` returns 403.

---

### Finding D-22: No length cap on `expires_after_minutes`; integer overflow / effectively-permanent shares

- **Severity:** Informational
- **Confidence:** High
- **Category:** design
- **Component:** `handlers/file_shares.go` :: `CreateFileShare`
- **Affected files / functions:** `handlers/file_shares.go:30, 112-116`

#### Description

```go
// handlers/file_shares.go:30
ExpiresAfterMinutes int `json:"expires_after_minutes"`
// handlers/file_shares.go:112-116
if request.ExpiresAfterMinutes > 0 {
    expiry := time.Now().Add(time.Duration(request.ExpiresAfterMinutes) * time.Minute)
    expiresAt = &expiry
}
```

No upper bound. A malicious or buggy client can set `ExpiresAfterMinutes = math.MaxInt`, causing `time.Duration * time.Minute` to overflow. Behavior under overflow: `time.Now().Add(huge_negative_duration_after_overflow)` produces a timestamp in the distant past, which would make the share appear *already expired* (the opposite of the attacker's likely intent — so this is self-DoS, not exploitable).

More practically: a client can set `ExpiresAfterMinutes = 525_600 * 100` (100 years) and the share is effectively permanent. This may be fine by design — but the e2e test at line 32 uses `43200` (30 days), suggesting the team has *some* idea of intended limits.

#### Recommendation

- Cap `ExpiresAfterMinutes` to a documented maximum (e.g. 525_600 == 1 year). Reject larger values with 400.
- Document the maximum in the API doc and the UI.

#### Suggested tests

- Handler test: `ExpiresAfterMinutes = math.MaxInt` returns 400.

---

### Finding D-23: Client-supplied `share_id` (not server-generated) gives a weak pre-image / pre-claim surface

- **Severity:** Informational
- **Confidence:** High
- **Category:** design
- **Component:** `handlers/file_shares.go` + `share-creation.ts`
- **Affected files / functions:** `handlers/file_shares.go:24-32, 52-71`; `share-creation.ts:91-104`

#### Description

`CreateFileShare` accepts a client-supplied `share_id`, validates it against `isValidShareID` (43-char base64url), and inserts as-is. The Go server function `generateShareID` (`handlers/file_shares.go:915-925`) exists but is not invoked by any handler I can find — it appears to be dead code.

The client generates the share ID with `randomBytes(32)` (`share-creation.ts:97`), giving 256 bits of CSPRNG entropy. **This is fine if the client honors its contract.** A malicious or compromised client can:

- Pick a low-entropy share_id (e.g. all-A's after format-validating). The server only checks length and character set, not entropy.
- Pre-claim share IDs (race condition: claim and squat).
- Pick a share_id that collides with an existing one — the server returns 409 and the legitimate creator's share is unaffected, so this is at most a DoS / annoyance.

#### Impact

- Limited. The threat model assumes the client is honest about share-ID entropy. A user who runs a malicious frontend can create their *own* shares with low entropy, exposing only their own shares to enumeration.
- The dead `generateShareID` function suggests an earlier server-side design that was deprecated. Per AGENTS.md greenfield posture, dead code should be removed.

#### Recommendation

- Either:
  - **Server-generates the share_id** (use `generateShareID`, ignore client input) — eliminates the entropy-honesty assumption.
  - Or **validate client share_id entropy** (count distinct chars, reject obvious low-entropy patterns) — weaker but cheaper.
- Remove the unused `generateShareID` function from `handlers/file_shares.go` (or document why it remains).

#### Cross-refs

- AGENTS.md "Greenfield App" — dead/deprecated functions should be flagged.

---

### Finding D-24: `isShareEndpoint` is dead code with wrong paths

- **Severity:** Informational
- **Confidence:** High
- **Category:** code quality
- **Component:** `handlers/rate_limiting.go`
- **Affected files / functions:** `handlers/rate_limiting.go:274-289`

#### Description

```go
// handlers/rate_limiting.go:274-289
func isShareEndpoint(path string) bool {
    shareEndpoints := []string{
        "/api/share/",
        "/shared/",
        "/api/files/share",
    }
    // ...
}
```

None of these prefixes match the actual share routes (`/api/shares` and `/api/public/shares/...` per `handlers/route_config.go`). The function has no callers in the codebase. Per AGENTS.md greenfield posture, this is dead/deprecated code that should be removed.

#### Recommendation

Delete `isShareEndpoint`. If it had a purpose (centralized share-route detection), reimplement it with the correct paths and use it consistently.

---

### Finding D-25: Owner JWT username appears in plaintext in InfoLogger on share creation

- **Severity:** Informational
- **Confidence:** High
- **Category:** privacy
- **Component:** `handlers/file_shares.go` :: `CreateFileShare`
- **Affected files / functions:** `handlers/file_shares.go:159-160`

#### Description

```go
// handlers/file_shares.go:159
logging.InfoLogger.Printf("Anonymous share created: file=%s, share_id=%s..., owner=%s",
    request.FileID, request.ShareID[:8], username)
database.LogUserAction(username, "created_share",
    fmt.Sprintf("file:%s, share:%s...", request.FileID, request.ShareID[:8]))
```

Plaintext `username` and full `file_id` in the InfoLogger output. AGENTS.md requires not logging PII; usernames are arguably the most direct PII. EntityID-based logging exists in other paths but is not used here.

#### Recommendation

Replace `owner=%s` with `owner_entity=%s` using the EntityID for the user. `database.LogUserAction` (audit-log table) is a separate concern — it is the canonical owner action log and can keep `username`; but the InfoLogger line is duplicate and is the log most likely to end up in a third-party log aggregator.

#### Cross-refs

- **D-15** (file_id + entity_id on anonymous side).
- **C-15** (Slice C: plaintext username + file_id in download InfoLogger).

---

### Finding D-26: Share envelope plaintext metadata can be used as a tracking channel by the owner

- **Severity:** Informational
- **Confidence:** Medium
- **Category:** design / privacy
- **Component:** `crypto/share_kdf.go` :: `ShareEnvelope`; `share-creation.ts`
- **Affected files / functions:** `crypto/share_kdf.go:108-114, 125-143`; `share-creation.ts:142-149`

#### Description

The share envelope embeds owner-supplied `filename`, `size_bytes`, `sha256`. These are inside the AEAD so only the recipient sees them — but **the owner controls them and the recipient cannot independently verify them**.

- `sha256` is verified by the recipient after download (good — tampering is detectable).
- `filename` and `size_bytes` are not verified. The owner can put arbitrary strings into `filename`, including tracking markers ("download-id-abc123.pdf"), social-engineering text, or unicode tricks.

This is largely an inherent property of share envelopes and not a "vulnerability" per se. Worth documenting.

#### Recommendation

- Document that filenames in shares are owner-controlled metadata and may differ from any server-side filename.
- Optionally: sanitize / cap `filename` length in `share-access.ts` rendering to prevent UX abuse (e.g. excessively long filenames overflowing the layout). `share-access.ts:197` uses `.textContent` which is XSS-safe; length capping is the only remaining issue.

---

### Finding D-27: Anonymous share GET endpoints lack explicit CSRF / Origin-check guard

- **Severity:** Informational
- **Confidence:** Medium
- **Category:** design
- **Component:** `handlers/file_shares.go` anonymous endpoints
- **Affected files / functions:** `handlers/file_shares.go:170-292, 569-689, 691-913`

#### Description

The anonymous share endpoints accept GET requests with no auth and no CSRF token. This is correct for the design — they are bearer-token-authenticated by the `X-Download-Token` header on chunk fetches and unauthenticated for envelope/metadata. But:

- Envelope/metadata responses are JSON, and could be embedded cross-origin via `<script src="...">` if the response started with executable content (it does not, so this is theoretical).
- Bearer token in a custom header (`X-Download-Token`) is not sent by browsers cross-origin without CORS preflight, so cross-origin exfiltration of chunks is gated by the CORS policy — which is set elsewhere (Caddyfile, Slice F).

No action required at this slice; **Slice F should verify the CORS policy** for `/api/public/shares/*` is restrictive (`Access-Control-Allow-Origin` matches the deployment origin only) and that `X-Download-Token` is not a "simple header" that bypasses preflight.

#### Cross-refs

- Slice F (CORS / Caddyfile).

---

## 3. Tables

### 3.1 Endpoint Review Table (share endpoints; for Slice E merge)

| Endpoint | Method | Auth required | Authorization rule | TOTP-gated? | Sensitive inputs | Sensitive outputs | Rate limited? | Issues |
|---|---|---|---|---|---|---|---|---|
| `/api/files/:fileId/envelope` | GET | Yes (JWT) | Owner of file | Yes | none | File metadata + per-file envelope params | implicit via JWT middleware | covered in Slice B/C |
| `/api/shares` | POST | Yes (JWT) | Owner of file_id | Yes | `share_id` (client-gen), `salt`, `encrypted_envelope`, `download_token_hash`, `expires_after_minutes`, `max_accesses` | `share_url` | None visible (TODO: spam-share rate limit) | D-09, D-22, D-23 |
| `/api/shares` | GET | Yes (JWT) | Caller's own shares | Yes | none | List of caller's shares with URLs and sizes | none | D-03 (writes in GET), D-09, D-25 |
| `/api/shares/:id/revoke` | POST | Yes (JWT) | Owner of share | Yes | `reason` (free-form string!) | Status | none | D-04 (free-form reason) |
| `/shared/:id` | GET | No | None (page render) | No (correct) | none | static HTML | `ShareEnumerationMiddleware` only | D-05 (missing per-share rate limit + timing), D-20 (no revoked check) |
| `/api/public/shares/:id` | GET | No | None | No (correct) | none | static HTML | enum + per-share + timing | OK |
| `/api/public/shares/:id/envelope` | GET | No | None | No (correct) | none | `salt`, `encrypted_envelope`, `size_bytes` | enum + per-share + timing | D-10, D-12, D-21 (size_bytes leak) |
| `/api/public/shares/:id/metadata` | GET | No | None | No (correct) | none | `file_id`, `size_bytes`, `chunk_count`, `chunk_size_bytes` | enum + per-share + timing | D-21 |
| `/api/public/shares/:id/chunks/:chunkIndex` | GET | No (bearer) | Valid `X-Download-Token` | No (correct) | `X-Download-Token` header | encrypted chunk bytes | enum + per-share + timing (per-failure only) | D-01, D-02, D-16, D-17 |

### 3.2 Crypto operations table (share-specific; for Slice G merge)

| Operation | Primitive | Key source | Nonce/IV | AAD | Storage | Issues |
|---|---|---|---|---|---|---|
| Share Key derivation | Argon2id | share password + random 32-byte salt + server-provided params | n/a | n/a | salt stored plaintext in DB | D-10 (offline cracking), D-12 (no params binding) |
| Share envelope encryption | AES-256-GCM | Share Key | random 12-byte IV per envelope (browser/Go CSPRNG) | `utf8(share_id + file_id)` (concat, no separator) | encrypted envelope bytes `[iv12 || ct || tag16]` stored plaintext in DB | D-12 (AAD ambiguity is mitigated only by fixed-length share_id) |
| Download token | random 32 bytes | CSPRNG | n/a | n/a | token kept by recipient; SHA-256(token) stored server-side | D-16, D-17 |
| Download token verification | SHA-256 + crypto/subtle constant-time compare | n/a | n/a | n/a | n/a | D-17 (decode-error path leaks oracle) |
| Share ID | random 32 bytes -> base64url | client CSPRNG (unverified by server) | n/a | n/a | plaintext in DB and URL | D-23 (client-supplied) |

### 3.3 Metadata exposure matrix (share-specific)

| Metadata item | Visible to anonymous recipient? | Visible to server? | Encrypted? | Authenticated? | Notes |
|---|---|---|---|---|---|
| Share password | only to recipient | **No** | n/a | n/a | client-only |
| Share salt | yes (envelope response) | yes (DB plaintext) | no | no | required for KDF |
| Argon2id params | yes (via `/api/config/argon2`) | yes | no | no | not bound to envelope (D-10/D-12) |
| Encrypted envelope blob | yes (envelope response) | yes | yes (AES-GCM-AAD) | yes (AEAD tag + AAD) | the asset under offline attack |
| FEK | only after envelope decrypt | **No** (only inside envelope ciphertext) | yes | yes | |
| Download token | only after envelope decrypt | only as SHA-256(token) | hashed at rest | n/a (bearer) | D-16, D-17 |
| Download token hash | no (server-side only) | yes (DB plaintext) | hash form | n/a | |
| Filename | only after envelope decrypt | no | yes (inside envelope) | yes | owner-controlled, D-26 |
| File size | yes (envelope and metadata responses) | yes | **no** | no | leak; D-21 |
| File chunk count | yes (metadata endpoint) | yes | **no** | no | leak; D-21 |
| File chunk size | yes (metadata endpoint) | yes | **no** | no | leak; D-21 |
| File SHA-256 | only after envelope decrypt | no | yes (inside envelope) | yes | owner-supplied; recipient verifies after download |
| Share ID | yes (URL) | yes (DB plaintext) | no | no | by design |
| File ID | yes (envelope/metadata responses) | yes (DB plaintext) | **no** | no | server-internal identifier exposed to anonymous recipients (D-15) |
| Owner username | no (anonymous flow) | yes (DB) | no | no | not exposed to recipient |
| Recipient identity | n/a | **no** (no PII) | n/a | n/a | EntityID HMAC only (D-11, D-19) |
| Access count | no (anonymous flow) | yes (DB) | no | no | owner-side only |
| Expiration timestamp | implicit via 403 | yes | no | no | by design |
| Revocation reason | yes (in 403 error message!) | yes | no | no | D-04 free-form leak |

### 3.4 Key hierarchy entries (Slice D additions)

| Key | Generated where | Entropy source | Storage | Leaves client? | Encrypts/authenticates | Rotated? | Destroyed when? | Compromise impact |
|---|---|---|---|---|---|---|---|---|
| Share Password | owner input | human | recipient browser RAM during unlock; never persisted | only as Argon2id input, never sent to server | derives Share Key | only by re-share with new password | recipient process exit | recovers all shares that used same password |
| Share Salt | owner client `randomBytes(32)` | CSPRNG | DB plaintext + envelope response | flows to server in create call and back to recipients in envelope fetch | seeds Argon2id | per-share | DB row deletion | needed to attack; alone is useless |
| Share Key | client Argon2id output | derived | RAM only | no | encrypts envelope JSON | per-share | wiped (Go: `clearBytes`; TS: `secureWipe` of key bytes; password string cannot be wiped) | recovers FEK + download token for that share |
| Download Token | owner client `randomBytes(32)` | CSPRNG | inside envelope (encrypted) + SHA-256 hash in DB | yes (recipient learns it after envelope decrypt) | bearer for chunk endpoint | per-share | DB row deletion | unlimited chunk fetches on that share (compounded by D-01) |
| Share ID | client `randomBytes(32)` + base64url | CSPRNG (client-controlled trust) | DB plaintext + URL | yes (visible to all) | identifier + AAD component | never | DB row deletion | enables targeted attack on that share |
| AAD bytes | UTF-8 `share_id + file_id` | derived | computed each op | yes (parts known to server) | binds envelope to share+file | n/a | n/a | AAD alone is useless |

---

## 4. N/A Items

| `idsrp.md` item | Status | Justification |
|---|---|---|
| Recipient public-key directory / PKI sharing | **N/A** | Arkfile shares are password-derived envelopes. No recipient identity, no public key. Confirmed by reading `share-crypto.ts` and `share_kdf.go`. |
| Server-controlled recipient public keys / key substitution attack | **N/A** | No recipient keys exist. |
| Share invitation messages / authenticated invitations | **N/A** | Sharing is URL+password; no invitation/notification path. |
| Folder-share recursion / descendant permissions | **N/A** | Arkfile is flat per-user; sharing is per-file only. |
| Re-sharing / nested share trees | **N/A** | A recipient who has decrypted an envelope holds the FEK and download token. They can pass the URL+password to a third party (out of band) — but the system has no "re-share" primitive and revocation semantics (D-13) cover this. |
| Sharing creates correct access to descendants when moving files in/out of shared folders | **N/A** | No folders. |
| Confused-deputy between owner, sender, recipient, viewer roles | **N/A** | Roles collapse: owner = sender; recipient = viewer. No deputy. |
| Tenant separation in sharing | **N/A** | Single tenant. |

---

## 5. Open Questions / Blocked-on-Developer Items

1. **Is the `max_accesses` semantic specified anywhere?** D-01 and D-02 are findings under the assumption that the intended semantic is "exactly this many *completed* downloads, total". If the intended semantic is "this many download *starts* (any chunk-0 fetch)", D-02 still stands and D-01 partially stands (chunks 1..N still bypass).
2. **Is `BASE_URL` mandatory in production deployments?** D-09 assumes the fallback path is reachable in production. Confirm whether `prod-deploy.sh` makes `BASE_URL` mandatory (would require checking the script, but per `.clinerules` we cannot read `.env` / `/opt/arkfile/etc/**` to validate the running config — please confirm).
3. **Is the daily EntityID rotation period configurable?** D-11 / D-19 — confirm that 24 h is the operationally chosen value and whether a longer window is feasible for rate-limit purposes only.
4. **Is the dead `generateShareID` function intentional (left in for the CLI client) or stray?** D-23.
5. **Is per-share-creation rate limiting enforced anywhere (e.g. account-level quota / spam-share guard)?** Not visible in this slice.

---

## 6. Testing Gaps (feeds Slice G)

Prioritized:

1. **Concurrency tests on `max_accesses` enforcement** (D-01, D-02). Easy to write; high value.
2. **AAD binding correctness across both Go and TS** including the variable-length scenario (D-12). The existing `TestShareEnvelopeEncryptDecrypt_WrongAAD` covers the happy path but not the ambiguity edge case.
3. **`/shared/:id` rate-limit and timing-protection coverage** (D-05). Currently no test for this route's middleware stack.
4. **Free-form `revoked_reason` leak** (D-04). No test asserts that anonymous recipients see only generic revocation messages.
5. **Negative test: invalid-base64 vs valid-base64-wrong-hash download tokens** (D-17). No timing test exists.
6. **Parameter-downgrade test** (D-10 / D-12). Once Argon2id params are bound to the envelope, a negative test should confirm tampered server params cannot trick a recipient into a weak KDF.
7. **`access_count` race test** (D-02) — see #1.
8. **Multi-instance enumeration coherence test** (D-18). Future, when multi-instance is supported.
9. **Anonymous-side log-hygiene test** (D-15, D-25). Assert that share access logs do not contain plaintext username, full file_id, or PII-equivalent identifiers.
10. **Property-based test for AAD construction**: for any (share_id, file_id) pair, the resulting AAD is unique (currently relies on fixed-length share_id, which is a brittle invariant).

---

## 7. Hardening / Non-Vulnerability Recommendations

1. **Bind Argon2id params to the share envelope** (D-10, D-12) — single highest-value hardening change in this slice.
2. **Atomic conditional UPDATE pattern** for `access_count` and `failed_count` (D-02, D-06). Apply throughout, not just for shares.
3. **Replace `fmt.Sprintf("%+v")` username extraction in `logging/entity_id.go`** with a small interface in a shared types package. Currently this works but is one rename away from a silent break in EntityID consistency — and could conceivably cause cross-user EntityID collisions if a username happens to contain a "Username:" substring. Slice E item; flagged here because it bleeds into share-rate-limit correctness.
4. **Add a `v` version byte to the share envelope JSON** (D-12). Cheap, future-proofing.
5. **Move share-list rendering off `innerHTML` to DOM-builder APIs** (D-14). Trivial refactor; eliminates the entire class of template-literal XSS risk in this surface.
6. **Sweeper for `share_access_attempts`** (D-07). Reuse the `billing/sweep.go` pattern.
7. **Document the actual share security model** in `docs/security.md`: offline brute force on stolen envelopes is the threat; share-password strength is the defense; revocation is future-fetch-only (D-10, D-13, D-19).
8. **Remove dead code**: `isShareEndpoint`, `generateShareID` if unused (D-24, D-23).
9. **Cap `revoked_reason` and `expires_after_minutes`** (D-04, D-22). Defensive input validation.
10. **Per-share total-bytes-served budget**, configurable by owner (D-16). Complementary to `max_accesses`.

---

## Summary of Findings

| Severity | Count | IDs |
|---|---:|---|
| Critical | 0 | — |
| High | 2 | D-01, D-10 |
| Medium | 9 | D-02, D-03, D-04, D-05, D-06, D-09, D-11, D-12, D-13 |
| Low | 10 | D-07, D-08, D-14, D-15, D-16, D-17, D-18, D-19, D-20, D-21 |
| Informational | 6 | D-22, D-23, D-24, D-25, D-26, D-27 |
| **Total** | **27** | |

### Top risks (rank order)

1. **D-10** — Stolen envelope = offline brute force; server operator can attack every share. Compounded by D-12 (no param binding).
2. **D-01** — `max_accesses` bypassable by skipping chunk 0; one-shot semantics broken.
3. **D-04** — Free-form `revoked_reason` leaks owner-controlled string to anonymous recipients; privacy/PII vector.
4. **D-02** — Race on `access_count` allows parallel double-spend on `max_accesses=1`.
5. **D-09** — Origin-header trust + non-mandatory `BASE_URL` = share-URL phishing primitive in misconfigured deployments.

### Cross-slice impact

- **Slice B `B-19`** (server-controlled crypto params) is the upstream of **D-10**; resolution of B-19 (or the param-binding fix in **D-12**) directly resolves much of D-10's offline-attack surface.
- **Slice C `C-01`/`C-02`/`C-03`** (chunk byte-range / no-AAD chunk reorder) apply equally to the anonymous chunk-download path here; not re-raised in this slice.
- **Slice E** will consume the Endpoint Review Table (§3.1) and verify TOTP-gating against the full route list.
- **Slice F** will consume the XSS / template-literal observations (D-14), Origin-trust (D-09), CSP for `shared.html`, and the CORS policy concern (D-27).
- **Slice G** will fold D-10 / D-13 / D-19 into the honest answer for `idsrp.md` §19 question 12 ("Can a malicious recipient access files after revocation?") and question 13 ("Does sharing rely on server-controlled public keys? If so, can the server substitute keys?").
