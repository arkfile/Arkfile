# Browser Streaming Download v2 — Service Worker Streaming

**Status:** Implemented and verified end-to-end on test.arkfile.net (2026-05-08).

Verified working with cryptographic SHA-256 confirmation (SW path) or
end-to-end completion (Blob fallback path):
- Brave regular tab — owner download, 2.47 GB AlmaLinux ISO, **SW path**.
- Firefox private tab — shared download, 2.47 GB, **SW path** (Firefox allows
  ephemeral SWs in private windows; cleared on session close).
- Tor Browser Safer mode — shared download, 2.47 GB, **Blob fallback path**
  completed end-to-end. KDF stage was 3–4 minutes (Tor Browser disables
  JIT at Safer level, which makes Argon2id much slower). This prompted
  adding a 5-second-quiet-period progress indicator on the share-access
  page; see §20.

The Service Worker streaming path is now the default download path for the
in-browser web client. The dead File System Access API (FSAPI) code has been
removed; the Blob path is preserved as a fallback for environments where
Service Worker registration fails. Streaming SHA-256 verification runs inline
on the SW path. See §19 below for the as-built reference and §20 for the
post-implementation diagnostic story (iframe-trigger fix + UI warning).

---

## 19. As-Built Reference (2026-05-08)

### Source files added

- `client/static/js/src/sw-download.ts` — Service Worker source (TypeScript,
  `lib: ["WebWorker"]` via `tsconfig.sw.json`). Bundled by Bun to
  `client/static/js/sw-download.js` (top-level so its default scope covers `/`).
- `client/static/js/src/files/sw-streaming-download.ts` — page-side wrapper:
  registration, `swStreamDownload(...)`, streaming SHA-256 hashing via
  `@noble/hashes`, AbortSignal cancel wiring, abort-aware pull race.
- `client/static/js/src/__tests__/sw-streaming-download.test.ts` — Bun unit
  tests covering registration plumbing, postMessage payload + ack, generator
  pumping, hash match/mismatch, and AbortSignal cancellation.
- `tsconfig.sw.json` — separate type-check config for the SW source so the
  WebWorker lib does not clash with the DOM lib used by the rest of the app.

### Source files modified

- `client/static/js/src/files/streaming-download.ts` — added SW path
  (`isSwAvailable()` -> `swStreamDownload(...)`), removed all FSAPI code
  (`streamChunksToDisk`, `fsapiHandlePromise`, `savedViaFileSystemAPI`).
  New result fields: `streamedViaSw`, `hashVerification`. Blob path preserved
  as fallback.
- `client/static/js/src/files/download.ts` — dropped sync FSAPI plumbing;
  surfaces `showWarning(...)` on hash mismatch.
- `client/static/js/src/files/list.ts` — dropped sync `showSaveFilePicker()`
  call from the Download click handler.
- `client/static/js/src/shares/share-access.ts` — same treatment; surfaces
  `showWarning(...)` on hash mismatch from share downloads.
- `client/static/js/src/app.ts` — registers the SW (best-effort) at app init.
- `client/static/js/package.json` — second `bun build` invocation emits the SW
  to top-level; `type-check`/`lint` scripts now also run the SW config.
- `tsconfig.json` — excludes `client/static/js/src/sw-download.ts` from the
  main DOM-lib type-check (it is checked separately via `tsconfig.sw.json`).
- `client/static/js/src/__tests__/streaming-download.test.ts` — removed FSAPI
  tests; new "Blob fallback path (SW unavailable)" suite.

### Server changes

- `handlers/middleware.go` — CSP gains `worker-src 'self'` so the SW can be
  registered.
- `handlers/route_config.go` — `Echo.File("/sw-download.js", ...)` serves the
  bundled SW; `GET /sw-download/*` returns 404 as defense-in-depth if the SW
  is not active.

### Build/deploy scripts updated

- `scripts/dev-reset.sh`, `local-deploy.sh`, `local-update.sh`,
  `test-deploy.sh`, `test-update.sh`, `prod-deploy.sh`, `prod-update.sh` —
  each script now also removes `client/static/js/sw-download.js{,.map}`
  before the TypeScript rebuild so the SW is regenerated fresh.
  `scripts/setup/build.sh` already copies all top-level `.js` files in
  `client/static/js/` to the build output (no change needed there).

### Decisions made during implementation

- **TypeScript source, top-level JS output.** The SW is authored in TypeScript
  for consistency with the rest of the codebase; only the compiled JS lives at
  `client/static/js/sw-download.js`. No JS source files were added to the repo.
- **Chunked-message fallback skipped.** Per the planning discussion, the
  cohort of users without transferable `ReadableStream` support (browsers
  older than Chrome 92, Firefox 100, Safari 16.4, Tor Browser 12.5+) is
  estimated at <0.5% and almost entirely unable to run Arkfile's existing
  WebCrypto/WASM stack regardless. Adding a chunked-message fallback would
  expand the trusted code surface without delivering meaningful coverage.
- **Streaming SHA-256 verification — implemented.** Plaintext bytes are
  hashed in-flight with `@noble/hashes` `sha256.create()` as they pass into
  the SW-bound stream. Mismatches are surfaced via `showWarning(...)` after
  the download completes (the file is on disk by then; we cannot un-write it,
  but we can loudly tell the user). No digest values, filenames, or UUIDs are
  ever logged to the console.
- **Cancel UX — wired through.** `AbortController.abort()` causes both
  (a) the page-side `pull()` to error its stream (responsive even mid-await
  via a `Promise.race` against the abort signal), and (b) a
  `{type:'cancel', uuid}` message to the SW so it cancels its outgoing stream
  to the browser's download manager.
- **Hash mismatch behavior:** warn-only after completion, with an additional
  console warning that omits all sensitive values. The user is shown a clear
  message recommending they delete and re-download the file.

### Verification

- `bun tsc --noEmit` (DOM lib): clean.
- `bun tsc --noEmit -p tsconfig.sw.json` (WebWorker lib, `skipLibCheck: true`
  to silence Bun-types vs WebWorker-lib internal conflicts): clean.
- `bun test`: 323 pass / 0 fail (up from 319; +5 new SW streaming tests, –1
  removed FSAPI test).
- Bundle sizes: `app.js` ~0.36 MB, `sw-download.js` ~4.1 KB (post-§20 fix; was
  ~3.4 KB before defensive consumed/grace logic was added).
- Cross-browser end-to-end manual verification on test.arkfile.net with the
  2.47 GB AlmaLinux ISO completed for **Brave regular tab** (owner download)
  and **Firefox private tab** (shared download). Both used the SW path and
  passed SHA-256 integrity verification end-to-end.

---

## 20. Post-Implementation Diagnostic Story (2026-05-08)

After §19 landed, the first deploy on test.arkfile.net failed for the 2.47 GB
file in Brave. The page log showed:

```
[arkfile-sw] download initiated via SW (bytes_expected=2477869106)
[arkfile-share] Chunk 1/148: fetch=…, decrypt=…, total_bytes=16777246
[arkfile-share] Chunk 2/148: fetch=…, decrypt=…, total_bytes=33554490
[arkfile-share] SW stream completed: ok=false, bytes_streamed=33554432, hash_verification=unavailable
[arkfile-share] Download failed at …ms: Stream cancelled
```

Brave displayed a popup error: **"File wasn't available on site."** Same
behavior reproduced consistently.

### Diagnostic technique that finally cracked it

The page console alone could not say what Brave was doing with the synthetic
`/sw-download/<uuid>` URL — SW-intercepted same-origin URLs do not appear in
the page Network tab. The breakthrough was:

1. **Open DevTools -> Application tab -> Service Workers**, click the **inspect**
   link next to `sw-download.js` to open a separate DevTools window for the SW
   process. The SW's own Console is the ONLY place the SW's `console.log` lines
   appear; they DO NOT echo into the page console.
2. With diagnostic `console.log` lines added inside the SW's fetch handler
   (`fetch: first match`, `fetch: subsequent match (already consumed)`,
   `fetch: no entry for path`), the SW Console was found to be **completely
   empty** during the failing run.

Empty SW Console + the page's `bytes_streamed=33554432` (exactly **2 × 16 MiB
chunks = 32 MiB**) is the diagnostic fingerprint of:

> The browser never issued a fetch the SW could intercept; the page-side
> `pull()` filled the internal transferred-stream buffer (which Chromium caps
> at 32 MiB when no consumer is reading from the receiving side) and then
> stopped, eventually erroring with "Stream cancelled."

In other words: our `<a download>` + `a.click()` invocation was silently
no-op'd by Chromium when the anchor had `display: none` and `rel="noopener"`.
This is a known Chromium quirk for SW-intercepted download URLs and is
documented in the StreamSaver.js issue tracker.

### The fix

Replace the anchor click with a hidden iframe:

```ts
// Old (silently no-op'd in Brave):
const a = document.createElement('a');
a.href = `/sw-download/${uuid}`;
a.download = filename;
a.style.display = 'none';
a.rel = 'noopener';
document.body.appendChild(a);
a.click();

// New (StreamSaver.js pattern, works reliably):
const iframe = document.createElement('iframe');
iframe.src = `/sw-download/${uuid}`;
iframe.style.cssText = 'position:fixed; left:-9999px; top:-9999px; width:1px; height:1px; border:0;';
document.body.appendChild(iframe);
setTimeout(() => iframe.parentNode?.removeChild(iframe), 60_000);
```

The iframe forces a real navigation request the SW reliably intercepts. After
this change Brave delivered the download cleanly through the SW Response.

### Defensive SW-side change (kept even after iframe fix)

Before discovering the anchor-click bug, we added a defensive change to the
SW's fetch handler: instead of one-shot deletion of `pendingStreams[uuid]`
on the first match, the entry is marked `consumed=true` and kept for a 30 s
post-consumption grace window. Any subsequent fetch for the same UUID returns
**empty 200**, not 404. This handles the rare case where a Chromium download
manager issues more than one fetch for the same SW URL on a single user
click (probe + commit). It costs us almost nothing and makes the SW resilient
to that whole class of edge cases. See `client/static/js/src/sw-download.ts`.

### UI gate for SW-unavailable + large-file recipients

The share-access page now **gates** the Download button with a warning
when `isSwAvailable() === false` AND `metadata.size_bytes > 2 GiB`. The
button is **disabled by default** in that case; a small "Download anyway"
override link beside it re-enables it for users who choose to accept the
risk.

Initial deployment surfaced a passive warning only:

> "This file is large. Your browser may not be able to complete the download
> in private/incognito mode. Options: open this link in a regular
> (non-private) browser tab, try a different browser (Firefox or Tor
> Browser), or use the arkfile-client CLI tool to download."

Two problems with that wording emerged from real-world testing:

1. **It implied private/incognito Chromium was the only failure mode.** Old
   Android Firefox in a private tab also fell back to Blob and exhibited
   exactly the same problem (proven by the absence of the upfront save-file
   prompt that Firefox shows on the SW path).
2. **It named "Firefox or Tor Browser" as alternatives.** Both can fail too
   on the exact same case — old Android Firefox + 2.1 GB + private tab
   crashed the tab and triggered the OS low-memory killer on a real test
   device, knocking the WiFi/VPN connection offline as collateral damage.
   We named browsers that we could not actually guarantee would work.

Replaced with deliberately neutral wording that makes no claim about the
user's specific setup (we don't detect browser/device/RAM):

> "Large file. For most reliable results with files this size, use a
> desktop browser, or the arkfile-client CLI."

Combined with the disabled-button gate, the user has to deliberately
opt in via "Download anyway" to attempt the Blob path on a >2 GiB file.

We **deliberately do not user-agent-detect** for this gate. We don't know
which browser/device/RAM the user has, and the failure modes vary widely.
The gate fires purely on the two facts we do know: SW could not register,
file is >2 GiB. That is information enough.

The Blob fallback path can fail in many ways depending on the user's
specific setup — anywhere from a silent timeout to an OS-level memory
pressure cascade that has been observed (on memory-constrained mobile
devices) to take down the user's WiFi/VPN connection while the tab dies.
Given that the failure mode can actively harm the user's network state,
the disabled-button-by-default policy is justified even though it is
slightly paternalistic.

### Cross-browser results (verified)

| Browser / Tab type | Result | Path used | Hash verification |
|---|---|---|---|
| Brave regular tab — 2.47 GB owner download | ✓ Works | SW | match |
| Firefox private tab (desktop) — 2.47 GB shared download | ✓ Works | SW | match |
| **Tor Browser Safer mode (desktop) — 2.47 GB shared download** | **✓ Works** | **Blob fallback** (Firefox-base, no Chromium 2 GB ceiling) | (download completed end-to-end; SHA-256 not separately verified) |
| **Old Android Firefox private tab — 2.1 GB shared download** | **✗ Fails** (silent; OS-OOM cascade observed taking down WiFi/VPN) | Blob fallback (Firefox-base did not register SW in private tab on this old version) | n/a |
| Brave private tab — 2.47 GB shared download | Predicted to fail; warning UI gates with override | n/a | n/a |
| Chrome / Edge | Untested; expected same as Brave | — | — |
| Tor Browser Standard mode (desktop) | Untested; expected same or better than Safer | — | — |

The "Old Android Firefox private tab" row was an observed real-world
failure that motivated the disabled-button gate documented above.
Diagnostic indicator: Firefox shows the OS save-file prompt
**immediately** when the SW path is taken (because the SW Response
includes `Content-Disposition: attachment` headers up front); on the
Blob path the prompt appears only after bytes are fully accumulated.
Absence of the upfront prompt is a reliable indicator that the SW
path was not used.

Firefox private tab using the **SW path** (not just falling back to Blob) was
a stronger result than the v2 plan §11.2 predicted — Firefox allows ephemeral
SWs in private windows that are cleared on session close. This means Firefox
private is a fully supported large-file recipient.

### Known cosmetic issue

The page's two byte counters disagree by exactly **4146 bytes** on completion:

```
SW stream completed: ok=true, bytes_streamed=2477864960, hash_verification=match
Download complete: chunks=148, bytes_decrypted=2477869106, …
```

`bytes_streamed` (counted inside `swStreamDownload`'s `pull()` after enqueue)
is 4146 bytes less than `bytes_decrypted` (counted in the chunk generator).
Both refer to the same plaintext stream. SHA-256 verification still matches
the full file, so this is an off-by-one in our own logging accounting, not a
data integrity issue. Investigation deferred — likely the last partial-chunk
fragment is being counted on one side but not the other.

### Diagnostic console.log lines retained

The `[arkfile-sw] fetch: …` log lines added during this round remain in
`sw-download.ts`. They are privacy-preserving (no UUIDs, no filenames in
output) and will substantially reduce the cost of diagnosing any future SW
streaming regression. The cost is three log lines per fetch — negligible.

### Slow-network UX improvement (always-show progress message)

Tor Browser Safer testing revealed that the share-envelope decryption stage
(Argon2id KDF + AES-GCM) can take **3–4 minutes** on devices/networks
constrained by Tor Browser's no-JIT policy. The page was previously stuck
on the literal status text "Verifying..." for the entire duration with no
indication that work was in progress, which led to the user reasonably
suspecting the page had hung.

**First attempt (failed): a 5-second quiet-period pattern.** For the first
5 s the status would read "Verifying..."; after that a `setTimeout` would
swap in an informative message + elapsed counter. The intent was to keep
the fast-desktop UX clean while informing slow-device users.

This did not work. `share-crypto.decryptShareEnvelope` runs Argon2id
**synchronously on the main thread**. While the KDF runs the JavaScript
event loop is fully blocked, so `setTimeout` callbacks cannot fire. After
3+ minutes the KDF returns and the page resumes; the unconditional cleanup
then cancels the queued timer before it gets a chance to execute. Net
result: users on slow devices/networks **never saw the message**, exactly
the opposite of the goal. The timer-based UX was a premise mismatch, not
a tunable parameter.

**Second attempt (worse): swap "Verifying..." with "Decrypting share
password... this can take a few minutes on older devices or slow networks."**

Two further problems:
- The phrasing "Decrypting share password" reveals more about the
  cryptographic flow than the more opaque "Verifying..." did. While the
  fact of client-side password-based decryption is not secret, surfacing
  it in the status line is unnecessary information leakage to anyone
  watching the user's screen.
- It was also subtly wrong: we do not "decrypt the password"; we derive a
  key from it via Argon2id and then decrypt an envelope.

**Current implementation: show a neutral progress message immediately when
unlock starts.** On click, status is set once to:
> "Verifying… can take a few minutes on slow networks/old devices."

…and a neutral matching `console.log` fires at the same time:
> `[arkfile-share] Verifying share access…`

Fast desktops see this for <1 s before the unlock completes; slow devices
see it for the entire duration. No oversold speed promise, no event-loop
assumption, no leak of crypto internals. Wording deliberately doesn't
name specific browsers; "older devices or slow networks" describes
conditions, not tools.

The proper structural fix — **moving Argon2id into a Web Worker** so the
event loop stays responsive during the KDF — is a separate, larger piece
of work and is deferred. Once that lands, a smarter quiet-period UX would
be possible.

### Lessons for future SW debugging

1. **The SW's own console is in a separate window.** Application tab ->
   Service Workers -> `inspect` next to the SW URL. Page console will not
   echo SW logs.
2. **Empty SW console + page-side `bytes_streamed` matching exactly the
   transferred-stream buffer cap (32 MiB on Chromium)** = the browser never
   issued a fetch the SW could intercept. The trigger is broken upstream;
   look at the page-side download trigger code, not the SW.
3. **`<a download>` + `a.click()` is unreliable for SW-served downloads on
   Chromium-based browsers** when the anchor has `display: none` and/or
   `rel="noopener"`. Use a hidden iframe whose `src` is the synthetic URL
   (StreamSaver.js pattern).
4. **Browsers' download managers can fire more than one fetch for the same
   SW URL on a single user click.** SWs that one-shot-delete their entry on
   first match cause the second fetch to 404 → "File wasn't available on
   site." Use mark-consumed + grace window instead.

---


## 1. Problem Statement

Arkfile is a privacy-first, end-to-end encrypted file vault. A core use case from `docs/AGENTS.md`:

> Consider an essential example of a user on a mobile device with 3 GB of RAM, attempting to encrypt/decrypt/upload/download a 6 GB file. Same for sharing: Consider an anonymous recipient trying to download and decrypt said 6 GB shared file on his mobile device with 3 GB of RAM. The app must work for all such users on constrained devices while respecting our security and privacy requirements.

For the in-browser web client, downloading large encrypted files (>2 GB) currently fails with `check internet connection` in Chromium-based browsers (Brave, Chrome, Edge), even when:

- All chunks download successfully
- All chunks decrypt successfully (peak heap stays at ~130 MB)
- The Blob is fully assembled in the browser's internal Blob store
- `URL.createObjectURL` returns a valid blob URL
- The `<a download>` anchor is clicked and the OS save dialog appears

The failure happens inside Chromium's download pipeline when it tries to read the >2 GB blob URL back out and stream it to the download manager. This is a Chromium architecture limitation.

This document plans the correct, universal fix: **Service Worker streaming**.

---

## 2. Failed Prior Approaches (Honest Documentation)

### Phase 1: OOM on collect-then-combine pattern (FIXED earlier in 2026)

The original `streaming-download.ts` collected all decrypted chunks into a `Uint8Array[]` and then `combineChunks()`'d them into one giant `Uint8Array`. For a 2.1 GB file the JS heap held simultaneously: chunk array (~2.1 GB), combined output (~2.1 GB), pending fetch buffers (up to ~2.1 GB), and the final Blob (~2.1 GB). Peak heap of 4–8 GB exceeded Chrome's per-context ArrayBuffer limit. Fixed by switching to incremental Blob construction (`new Blob([existingBlob, chunk])` per chunk), keeping data in the browser's internal Blob store off the JS heap. Peak heap dropped to ~16 MiB (one chunk).

### Phase 2: File System Access API (DEAD CODE in target environment)

After Phase 1, downloading a 2.31 GB AlmaLinux ISO via a public share link in Brave still failed at the very end with `check internet connection` — the symptom that prompted this work in 2026-05-07.

Diagnosis: Chromium-based browsers cannot serve blob URLs for Blobs above ~2 GB through their internal download pipeline. The blob is fully assembled, but the download manager fails to pipe it to disk.

Initial fix attempt: use `showSaveFilePicker()` from the File System Access API to write chunks directly to disk, bypassing the blob URL entirely. The implementation included the critical detail of calling `showSaveFilePicker()` synchronously inside the click event (before any `await`) to satisfy browser user-gesture requirements. Implemented across `share-access.ts`, `list.ts`, `download.ts`, and `streaming-download.ts`. All 319 frontend unit tests passed.

**Production result on `test.arkfile.net` (2026-05-07):** the FSAPI path was never taken. Console diagnostic confirmed `window.showSaveFilePicker` is `undefined` in Brave on the share page. Brave's privacy posture removes the FSAPI from the global `window` object on regular pages — likely because FSAPI is classified as a fingerprinting vector. The code's existence-check (`'showSaveFilePicker' in window`) correctly fell through to the Blob path, which then failed on the >2 GB file.

The FSAPI path is, in our most important target environment (Brave with default settings), dead code. Firefox doesn't ship FSAPI at all. Tor Browser doesn't ship it. Even on Chrome proper, FSAPI requires user permission in some configurations. We cannot rely on it.

### Phase 3: Service Worker streaming (this document)

The architecturally correct fix.

---

## 3. Why Service Workers, and Why They Work in Tor Browser

A Service Worker (SW) is a browser-managed background script registered against an origin/scope that can intercept `fetch` events from pages within that scope. The SW can return a synthetic `Response` whose body is a `ReadableStream`. The browser treats this exactly like any other HTTP response — when the response carries `Content-Disposition: attachment`, the browser streams it directly to its download manager with no involvement of blob URLs.

### Properties relevant to Arkfile's privacy and use cases

- **No fingerprinting vector.** Service Workers are a foundational web platform feature, not classified as a fingerprinting surface by Brave Shields, uBlock, or similar tools. They are not blocked by privacy-focused configurations.
- **No 2 GB ceiling.** The `Response`/`ReadableStream` path bypasses Chromium's blob URL limitation entirely.
- **Memory bounded.** Chunks flow through the stream one at a time and are garbage-collected after consumption. Peak heap stays at ~16 MiB regardless of total file size.
- **Same-origin only.** The SW intercepts only same-origin synthetic URLs (`/sw-download/<uuid>`); it never makes network requests of its own. Tor circuit usage is unchanged from today's chunk fetch behavior.

### Tor Browser support (first-class)

Tor Browser is built on Firefox ESR. Recent versions (Tor Browser 12+, since 2023) ship with **Service Workers ENABLED by default** at both `Standard` and `Safer` security levels. Only at `Safest` does Tor Browser disable JavaScript entirely — at which point no JavaScript-based application works, not specifically Arkfile. This is a deliberate user choice.

Therefore, **Tor Browser at Standard or Safer is a fully supported client for SW streaming**, with the same code path as Brave/Chrome/Firefox/etc. There is no special-casing, no "use CLI for >1.5 GB" message, no apologetic UX for Tor users.

Privacy properties specifically for Tor Browser users:
- The synthetic `/sw-download/<uuid>` URL is intercepted by the SW and never reaches the network. Tor exit nodes see nothing about the download UUID, filename, or content.
- The chunk fetches from `/api/public/shares/:id/chunks/:n` continue to flow through the Tor circuit exactly as they do today.
- The SW's in-memory `Map<uuid, ReadableStream>` is non-persistent and tied to the SW's lifetime. No persistent state is added.
- No new fingerprinting opportunities. The SW registration itself is invisible to the network observer; only same-origin in-browser activity.

---

## 4. Architecture

```
┌────────────────────────────┐                   ┌──────────────────────────────┐
│  Page (share-access.ts /   │                   │  Service Worker              │
│  download.ts / list.ts)    │                   │  (/sw-download.js)           │
│                            │                   │                              │
│ 1. Click Download          │                   │                              │
│                            │                   │  pendingStreams: Map<        │
│ 2. Build async generator   │                   │    uuid,                     │
│    over decrypted chunks   │                   │    {stream, filename,        │
│    (existing code reused)  │                   │     contentLength}>          │
│                            │                   │                              │
│ 3. Wrap generator in a     │                   │                              │
│    ReadableStream          │                   │                              │
│                            │                   │                              │
│ 4. Generate uuid           │                   │                              │
│                            │                   │                              │
│ 5. postMessage to SW:      │  ──────────────▶  │  onmessage: store entry      │
│    { type: 'init',         │                   │  in pendingStreams,          │
│      uuid, filename,       │                   │  reply { type: 'ack', uuid } │
│      contentLength,        │  ◀──────────────  │                              │
│      stream (transferred)} │                   │                              │
│                            │                   │                              │
│ 6. Click hidden            │                   │                              │
│    <a href="/sw-download/  │                   │                              │
│       <uuid>?filename=..." │                   │                              │
│       download>            │                   │                              │
│                            │                   │                              │
│ 7. Browser fetches the URL │  ──────────────▶  │  onfetch:                    │
│                            │                   │   match /sw-download/<uuid>  │
│                            │                   │   look up pendingStreams     │
│                            │                   │   respondWith(Response(      │
│                            │  ◀──────────────  │     stream,                  │
│                            │  Response with    │     {Content-Disposition,    │
│                            │  ReadableStream   │      Content-Type,           │
│                            │                   │      Content-Length?}        │
│                            │                   │   ))                         │
│                            │                   │                              │
│ 8. Browser sees a normal   │                   │                              │
│    HTTP attachment         │                   │                              │
│    response → streams to   │                   │                              │
│    download manager        │                   │                              │
│                            │                   │                              │
│ 9. SW's pendingStreams[    │                   │                              │
│    uuid] entry deleted     │                   │                              │
│    on stream completion    │                   │                              │
└────────────────────────────┘                   └──────────────────────────────┘
```

The actual encrypted-chunk fetching, AES-GCM decryption, retry logic, and progress reporting all happen in the **page** (not the SW), reusing the existing implementation entirely. The SW is a passive forwarder of the already-decrypted byte stream.

---

## 5. File-by-File Implementation Plan

### 5.1 New file: `client/static/sw-download.js`

Top-level path (NOT inside `/js/dist/`) so its scope can cover `/sw-download/*`. Plain JavaScript (not TypeScript-compiled) to avoid build-tool complications.

```javascript
// sw-download.js — Arkfile streaming download Service Worker
//
// Intercepts /sw-download/<uuid>?filename=... requests from same-origin pages
// and responds with a Content-Disposition: attachment Response whose body is
// a ReadableStream provided by the page via postMessage.
//
// PRIVACY: This SW makes NO network requests of its own. It only intercepts
// same-origin synthetic URLs and forwards already-decrypted byte streams from
// the page to the browser's download manager. No data leaves the device.

const CACHE_NONE = null; // No caching; SW is purely a stream forwarder.
const SW_VERSION = '1';  // Bump on code changes to force update.

// Map<uuid, { stream: ReadableStream, filename: string, contentLength?: number, expiresAt: number }>
const pendingStreams = new Map();

// Stale-stream cleanup (5 min TTL — page should trigger fetch within seconds)
setInterval(() => {
  const now = Date.now();
  for (const [uuid, entry] of pendingStreams) {
    if (entry.expiresAt < now) {
      try { entry.stream.cancel('expired'); } catch (_) {}
      pendingStreams.delete(uuid);
    }
  }
}, 60 * 1000);

self.addEventListener('install', (event) => {
  // Activate new SW immediately, replacing any old version.
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  // Take control of pages immediately, even on first registration.
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data !== 'object') return;

  if (data.type === 'init' && data.uuid && data.stream) {
    pendingStreams.set(data.uuid, {
      stream: data.stream,
      filename: data.filename || 'download',
      contentLength: data.contentLength,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    // Acknowledge so page knows it's safe to navigate to the download URL.
    if (event.source) event.source.postMessage({ type: 'ack', uuid: data.uuid });
  } else if (data.type === 'ping') {
    if (event.source) event.source.postMessage({ type: 'pong', version: SW_VERSION });
  } else if (data.type === 'cancel' && data.uuid) {
    const entry = pendingStreams.get(data.uuid);
    if (entry) {
      try { entry.stream.cancel('user-cancelled'); } catch (_) {}
      pendingStreams.delete(data.uuid);
    }
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith('/sw-download/')) return;

  const uuid = url.pathname.substring('/sw-download/'.length);
  const entry = pendingStreams.get(uuid);
  if (!entry) {
    event.respondWith(new Response('SW: stream not found or expired', {
      status: 404,
      headers: { 'Content-Type': 'text/plain' },
    }));
    return;
  }

  pendingStreams.delete(uuid); // One-shot consumption.

  // Encode filename for Content-Disposition (RFC 5987)
  const safeName = encodeURIComponent(entry.filename).replace(/['()]/g, escape);
  const headers = {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename*=UTF-8''${safeName}`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  if (entry.contentLength != null) {
    headers['Content-Length'] = String(entry.contentLength);
  }

  event.respondWith(new Response(entry.stream, { status: 200, headers }));
});
```

Approximate length: ~80 lines of well-commented code.

### 5.2 New file: `client/static/js/src/files/sw-streaming-download.ts`

Page-side wrapper. Exports the SW registration and the per-download invocation.

```typescript
const SW_URL = '/sw-download.js';
const SW_SCOPE = '/sw-download/';

let registration: ServiceWorkerRegistration | null = null;

export async function registerSwDownload(): Promise<boolean> {
  if (!('serviceWorker' in navigator)) return false;
  try {
    registration = await navigator.serviceWorker.register(SW_URL, { scope: SW_SCOPE });
    // Wait for activation
    if (registration.active) return true;
    await new Promise<void>((resolve) => {
      const sw = registration!.installing || registration!.waiting;
      if (!sw) return resolve();
      sw.addEventListener('statechange', () => {
        if (sw.state === 'activated') resolve();
      });
    });
    return true;
  } catch (err) {
    console.warn('[arkfile-sw] SW registration failed:', err);
    return false;
  }
}

export function isSwAvailable(): boolean {
  return navigator.serviceWorker?.controller != null;
}

/**
 * Stream a decrypted file to disk via the Service Worker.
 *
 * @param filename  Suggested filename (used in Content-Disposition).
 * @param contentLength  Plaintext byte length (for download manager progress).
 * @param generator  Async generator yielding decrypted Uint8Array chunks.
 * @param signal  AbortSignal for user-initiated cancellation.
 * @returns Resolves when browser has accepted the download (the anchor click).
 */
export async function swStreamDownload(
  filename: string,
  contentLength: number,
  generator: AsyncGenerator<Uint8Array>,
  signal?: AbortSignal,
): Promise<void> {
  const ctrl = navigator.serviceWorker.controller;
  if (!ctrl) throw new Error('Service Worker is not active');

  const uuid = crypto.randomUUID();
  const stream = generatorToStream(generator, signal);

  // Send init to SW; await ack via MessageChannel.
  await new Promise<void>((resolve, reject) => {
    const channel = new MessageChannel();
    channel.port1.onmessage = (ev) => {
      if (ev.data?.type === 'ack' && ev.data.uuid === uuid) {
        resolve();
      } else {
        reject(new Error('SW did not ack stream init'));
      }
    };
    ctrl.postMessage(
      { type: 'init', uuid, filename, contentLength, stream },
      [stream as unknown as Transferable, channel.port2],
    );
    setTimeout(() => reject(new Error('SW ack timeout')), 5000);
  });

  // Trigger the download by clicking a hidden anchor.
  const a = document.createElement('a');
  a.href = `/sw-download/${uuid}`;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => a.remove(), 1000);
}

/** Wrap an async generator of Uint8Array chunks into a ReadableStream. */
function generatorToStream(
  generator: AsyncGenerator<Uint8Array>,
  signal?: AbortSignal,
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (signal?.aborted) {
          controller.error(new Error('Download cancelled'));
          await generator.return?.(undefined);
          return;
        }
        const { value, done } = await generator.next();
        if (done) {
          controller.close();
        } else if (value) {
          controller.enqueue(value);
        }
      } catch (err) {
        controller.error(err);
        try { await generator.return?.(undefined); } catch (_) {}
      }
    },
    cancel(_reason) {
      try { generator.return?.(undefined); } catch (_) {}
    },
  });
}
```

Approximate length: ~100 lines.

### 5.3 Modify `client/static/js/src/app.ts`

At app initialization, register the SW and store the result in module state. Expose a function `swDownloadAvailable()` that returns `true` if SW streaming is ready.

```typescript
// In app init (early, before any download UI is rendered):
import { registerSwDownload } from './files/sw-streaming-download';
const swReady = await registerSwDownload();
if (swReady) console.log('[arkfile] SW streaming download ready');
else console.warn('[arkfile] SW streaming unavailable; large file downloads may fail');
```

### 5.4 Modify `client/static/js/src/files/streaming-download.ts`

Add a third path: SW streaming. New decision logic:

```
if isSwAvailable():
    use SW streaming path (preferred)
else:
    use Blob fallback path (safety net only; works for files <2 GB on
    Chromium and <several GB on Firefox-derived browsers including Tor)
```

The FSAPI code is **removed entirely**. The `fsapiHandlePromise` field on `StreamingDownloadOptions` is removed. The `savedViaFileSystemAPI` field on `StreamingDownloadResult` is removed. New fields:

```typescript
export interface StreamingDownloadResult {
  success: boolean;
  filename?: string;
  sha256sum?: string;
  error?: string;
  /** True if the SW streaming path was used. */
  streamedViaSw?: boolean;
  /** Object URL for the assembled Blob; only on the Blob fallback path. */
  blobUrl?: string;
}
```

The chunk generators (`makeFileChunkGenerator`, `makeShareChunkGenerator`) are unchanged. They are now consumed either by the SW streaming wrapper (preferred) or by the Blob accumulator (fallback).

### 5.5 Modify `client/static/js/src/shares/share-access.ts`

The synchronous `showSaveFilePicker()` click logic is removed. The Download button click handler becomes a simple async function:

```typescript
downloadBtn.onclick = async () => {
  console.log('[arkfile-share] Download button clicked');
  await this.downloadFile(filename, fek, sha256);
};
```

The `downloadFile` method internally calls `downloadSharedFileChunked()` which uses the SW path when available.

### 5.6 Modify `client/static/js/src/files/list.ts` and `client/static/js/src/files/download.ts`

Same treatment: remove the synchronous `showSaveFilePicker()` calls and the `fsapiHandlePromise` argument. Click handlers become simple async invocations.

### 5.7 Modify `handlers/middleware.go`

Update the CSP to explicitly allow Service Worker registration:

```go
csp := "default-src 'self'; " +
    "script-src 'self' 'wasm-unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "connect-src 'self' data: blob:; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'; " +
    "frame-ancestors 'none'; " +
    "worker-src 'self'; " +    // NEW: allow SW from same origin
    "upgrade-insecure-requests"
```

The `worker-src 'self'` directive explicitly permits Service Worker scripts from the same origin. Without this, some strict browsers may reject the registration.

### 5.8 Modify `client/static/index.html` and `client/static/shared.html`

No changes required for the HTML itself. The SW is registered programmatically by `app.ts`.

### 5.9 Server-side route safety

The server should return 404 for any GET request to `/sw-download/*` so that if the SW is not active for any reason, the page's anchor click fails fast with a network error rather than being mistakenly handled as a real route. Add a tiny route in `handlers/route_config.go`:

```go
// SW-intercepted paths: if SW is not active, return 404 immediately.
// These paths should never be served by the server.
e.GET("/sw-download/*", func(c echo.Context) error {
    return echo.NewHTTPError(http.StatusNotFound, "Service Worker not active")
})
```

### 5.10 Tests: `client/static/js/src/__tests__/streaming-download.test.ts` and new `sw-streaming-download.test.ts`

Update existing tests:
- Remove tests for the FSAPI path (FSAPI code is gone).
- Update Blob fallback tests to reflect that Blob is now a true fallback only.

Add new tests in `sw-streaming-download.test.ts`:
- Mock `navigator.serviceWorker.controller` and verify `postMessage` is called with the correct payload (`type: 'init'`, uuid, filename, stream).
- Test `generatorToStream`: feed it a mock async generator producing 3 chunks, consume the resulting ReadableStream via `getReader()`, verify all 3 chunks emerge in order, verify the stream closes after the generator is exhausted.
- Test cancellation: abort the signal mid-stream, verify `controller.error()` is called and `generator.return()` is invoked for cleanup.
- Test SW unavailable: simulate `navigator.serviceWorker.controller === null`, verify `swStreamDownload` throws.

---

## 6. Message Protocol (Concrete Types)

```typescript
// Page → SW
type InitMessage = {
  type: 'init';
  uuid: string;
  filename: string;
  contentLength?: number;
  stream: ReadableStream<Uint8Array>; // Transferred via postMessage transfer list
};

type CancelMessage = {
  type: 'cancel';
  uuid: string;
};

type PingMessage = { type: 'ping' };

// SW → Page
type AckMessage = { type: 'ack'; uuid: string };
type PongMessage = { type: 'pong'; version: string };
```

The page transfers the `ReadableStream` to the SW using `postMessage(message, [stream, port])` where the second argument is the transfer list. After transfer, the page no longer has access to the stream — it lives in the SW's context. This is supported in Brave/Chrome 92+, Firefox 100+, Safari 16.4+.

For the rare browser that lacks transferable `ReadableStream` support, a chunked-message fallback would send chunks one at a time via a `MessageChannel`. This fallback is documented but deferred to a follow-up task — current target browsers (including Tor Browser 12+) all support transferable streams.

---

## 7. Browser Compatibility Matrix (Corrected)

| Browser | SW Streaming (preferred) | Blob Fallback (safety net) | First-Class? |
|---|---|---|---|
| **Tor Browser 12+ (Standard/Safer)** | **Works** | Works to several GB (Firefox base) | **Yes** |
| Tor Browser 12+ (Safest) | N/A — JS off by user choice | N/A — JS off by user choice | User opted out |
| Brave (any modern version, shields up or down) | Works | Fails on >2 GB | Yes |
| Chrome 89+ | Works | Fails on >2 GB | Yes |
| Edge 89+ | Works | Fails on >2 GB | Yes |
| Firefox 100+ | Works | Works to several GB | Yes |
| Firefox 80–99 | Works (no transferable stream — chunked-message fallback) | Works | Yes (with fallback) |
| Safari 16.4+ | Works | Works | Yes |
| Safari 14–16.3 | Works (chunked-message fallback) | Works | Yes (with fallback) |
| Mobile Brave/Chrome | Works | Fails on >2 GB | Yes |
| Mobile Firefox / Tor Browser Android | Works | Works | Yes |
| Mobile Safari iOS 16.4+ | Works | Works | Yes |

**Tor Browser is a first-class supported client.** The same SW streaming path used by Brave/Chrome/Firefox is used in Tor Browser. There is no special-casing, no apologetic UX, no "use CLI" message for Tor users. The SW makes no network requests; all traffic flows through the existing chunk fetch endpoints over the user's Tor circuit exactly as today.

---

## 8. SW Lifecycle Concerns and Mitigations

### 8.1 First registration after deploy

When a user loads the page after a deployment that includes a new SW, the SW downloads but doesn't take control until all old tabs close (default Service Worker behavior). 

**Mitigation:** the SW calls `self.skipWaiting()` in its `install` handler and `self.clients.claim()` in its `activate` handler. This forces immediate replacement of any old SW and immediate control of all open tabs. The result: a single page reload after deploy is sufficient.

### 8.2 SW updates

When the SW code changes, browsers detect the change by byte-comparing the script. To force updates after a deploy, the registration script can be cache-busted (e.g., `/sw-download.js?v=<git-hash>`). For a greenfield app this is overkill — `skipWaiting`/`clients.claim` plus a normal page reload after deploy is sufficient.

### 8.3 SW eviction

Browsers may evict idle SWs to save memory. The page's `registerSwDownload()` is idempotent — calling it on every page load re-registers if needed.

### 8.4 Page closed mid-download

If the user closes the page while a download is in progress, the source generator is cancelled, which closes the `ReadableStream`, which causes the SW's `Response` body to end. The browser's download manager sees the connection close and the download fails. This is identical to today's behavior with the Blob path and matches the user's expectation when closing a tab during a regular download.

### 8.5 Concurrent downloads

Each download generates a unique UUID and occupies a separate entry in the SW's `pendingStreams` Map. Concurrent downloads are fully supported.

### 8.6 SW registration fails

Some niche environments (private browsing modes that disable SW, browsers with persistent cookies/storage disabled, very old browsers) may fail to register the SW. In this case `registerSwDownload()` returns `false` and the page falls through to the Blob fallback. For files >2 GB in such an environment on Chromium-based browsers, the user will see the existing failure mode. This is rare enough to be acceptable; the WIP doc and CLI guidance cover this case.

### 8.7 Tor Browser and SW persistence

Tor Browser intentionally does NOT persist Service Worker storage across browser sessions (it follows the same isolation rules as cookies and other storage). Each new Tor Browser session re-registers the SW on first page load. This is fine — registration is fast and idempotent.

---

## 9. Streaming Source: Wrapping Async Generators

The page wraps the existing chunk generators (`makeFileChunkGenerator`, `makeShareChunkGenerator`) in a `ReadableStream` whose `pull()` method calls the generator's `next()`. The generator handles all the AES-GCM decryption, retry logic, and progress reporting unchanged. Cancellation propagates from the stream's `cancel()` to the generator's `return()`.

This is the key composability win: zero changes to the existing chunk pipeline; only the consumer changes.

```typescript
// In streaming-download.ts, the new SW path:
async downloadSharedFile(
  shareId: string,
  fek: Uint8Array,
  shareMetadata?: { filename?: string; sha256?: string },
): Promise<StreamingDownloadResult> {
  // ... fetch metadata, validate ...

  const generator = this.makeShareChunkGenerator(shareId, metadata, fek);

  if (isSwAvailable()) {
    await swStreamDownload(
      shareMetadata?.filename ?? 'shared-file',
      metadata.size_bytes,
      generator,
      this.options.abortController?.signal,
    );
    return { success: true, filename: shareMetadata?.filename, streamedViaSw: true };
  }

  // Fallback: Blob accumulation (existing code path)
  const blobUrl = await this.streamChunksToBlob(generator, ...);
  return { success: true, filename: shareMetadata?.filename, blobUrl };
}
```

---

## 10. Server-Side Changes

**None to existing functionality.**

One additive route for safety: a 404 catch-all on `/sw-download/*` so that requests in this path that somehow reach the server (SW not active, edge case) fail fast rather than being treated as real routes. This is purely defense-in-depth.

All existing endpoints are unchanged:
- `/api/public/shares/:id/envelope`
- `/api/public/shares/:id/metadata`
- `/api/public/shares/:id/chunks/:n`
- `/api/files/:id/meta`
- `/api/files/:id/chunks/:n`

All existing auth and middleware unchanged: JWT, OPAQUE, share download token validation, rate limiting, timing protection, CSP (only the `worker-src` addition).

---

## 11. Testing Strategy

### 11.1 Unit (Bun, in `__tests__`)

- `sw-streaming-download.test.ts` (NEW):
  - `registerSwDownload`: mock `navigator.serviceWorker.register`, verify scope and URL.
  - `swStreamDownload` happy path: mock `navigator.serviceWorker.controller`, verify postMessage payload (uuid, filename, contentLength, stream in transfer list); verify the anchor element is created with the correct `href`.
  - `swStreamDownload` no SW: simulate `controller === null`, verify it throws with a clear error.
  - `generatorToStream`: feed it a generator producing 3 chunks `[a, b, c]`, read the resulting ReadableStream, verify chunks emerge in order and the stream closes.
  - Cancellation: abort the signal, verify `controller.error()` and `generator.return()` are called.

- `streaming-download.test.ts` (UPDATED):
  - Remove FSAPI-path tests.
  - Update fallback test: when `navigator.serviceWorker.controller` is `null`, verify the Blob fallback is taken and `blobUrl` is returned.
  - When SW is available, verify the SW path is taken (`streamedViaSw === true`) and no `blobUrl` is set.

### 11.2 Integration (manual, in real browsers)

For each of: Brave (shields up), Brave (shields down), Chrome, Firefox, Tor Browser (Standard), Tor Browser (Safer):

1. Deploy via `prod-update.sh` to test.arkfile.net (or `dev-reset.sh` for local).
2. Hard-reload the page.
3. Verify `[arkfile] SW streaming download ready` appears in console.
4. Generate a share link for a 2.3 GB file (the AlmaLinux ISO from the original bug report).
5. Click the share link, enter password, click Download.
6. Verify the OS Save dialog appears immediately or the file starts downloading immediately to the default Downloads folder (browser configuration dependent).
7. Verify the file completes and `sha256sum` of the saved file matches the expected hash in the share envelope.
8. During the download, monitor the browser's task manager (about:performance in Firefox/Tor, Brave's task manager in Brave) to verify memory usage stays below ~300 MB.

### 11.3 Playwright (`scripts/testing/e2e-playwright.ts`)

Add a new test: register the SW, perform a small share download, verify the file integrity matches. Large file (>2 GB) testing in Playwright is impractical; the manual integration tests above cover that.

### 11.4 SHA-256 verification

The page's `downloadSharedFile()` returns `sha256sum` from the share envelope. Currently the page does not verify the downloaded bytes against this hash, because hashing the full file would defeat the streaming approach. Verification should be done via a `TransformStream` that hashes plaintext chunks as they flow past, finalizing on stream close — this is a small enhancement to add as part of this work, allowing a post-download integrity check displayed in the UI without buffering. The hash result can be logged to console and optionally surfaced via a "Verify integrity" button.

---

## 12. Rollout Plan

1. Implement everything in a feature branch.
2. `sudo bash scripts/dev-reset.sh` and run all unit tests; all 319+ tests must pass.
3. Run `bash scripts/testing/e2e-test.sh` to verify the existing CLI e2e tests still pass (they should — the CLI uses no browser code).
4. Run `sudo bash scripts/testing/e2e-playwright.sh` to verify the Playwright tests pass with the new SW path.
5. Deploy to `test.arkfile.net` via `sudo bash scripts/prod-update.sh`.
6. Manual verification across Brave (shields up), Chrome, Firefox, Tor Browser (Standard), with the original 2.3 GB AlmaLinux ISO.
7. If all passes, the doc moves from `docs/wip/` to a status of "completed" and a brief note is added to `README.md` or `docs/setup.md` mentioning that downloads use Service Workers.
8. Archive the old `browser-streaming-download.md` and this v2 doc once code lands.

---

## 13. Code Removed After This Lands

When the SW path is verified working in production:

- All FSAPI code in `streaming-download.ts` (the `streamChunksToDisk` FSAPI branch, the `fsapiHandlePromise` option).
- The synchronous `showSaveFilePicker()` calls in `share-access.ts`, `list.ts`, `download.ts`.
- The `triggerBrowserDownloadFromUrl` function (replaced by the SW + anchor click pattern).
- `StreamingDownloadResult.savedViaFileSystemAPI` field.
- The Blob accumulation path is **kept** as a fallback for SW-unavailable environments but simplified; documentation notes the size limit on Chromium.

This dead-code removal is part of the work, not a separate task.

---

## 14. Alternatives Considered and Rejected

### Multi-part Blob splits

Split the >2 GB Blob into multiple sub-2 GB Blobs, trigger N sequential downloads. Bad UX (user has to reassemble files), incompatible with `Content-Disposition` single-file semantics, still uses Blob URLs (still has issues with concurrency on Chromium). **Rejected.**

### Server-side decryption proxy

Have the server decrypt and stream plaintext to the browser via standard HTTP. Violates the privacy model — the server would see plaintext. **Rejected hard, contradicts AGENTS.md.**

### Page reload trick

Reload the page after the user clicks Download to bypass user-gesture timing for FSAPI. Doesn't solve the 2 GB ceiling, doesn't help in Brave with shields up. **Rejected.**

### WebTransport / WebSocket streaming

Build a server-side counterpart that streams encrypted bytes via WebSocket and decrypt in the page. Overkill, requires server infra, doesn't help with Tor (WebSockets work in Tor but add no benefit over the existing chunk fetch model). **Rejected.**

### Wait for browsers to fix it

Chromium's blob URL ceiling has been a known issue since 2017. There is no fix scheduled. We cannot wait. **Rejected.**

### Use StreamSaver.js as a dependency

Adds a 600+ line MIT-licensed dependency for code that is genuinely small (~250 lines total of our own SW + wrapper). Adding a dependency for a privacy-critical code path expands the trusted code base. **Rejected** in favor of a small, auditable in-house implementation. We use StreamSaver.js as a reference for technique only.

---

## 15. Effort Estimate

| Task | Estimate |
|---|---|
| Service Worker file (`sw-download.js`) | 2–3 hours |
| Page-side wrapper (`sw-streaming-download.ts`) | 2–3 hours |
| Refactor `streaming-download.ts`, `share-access.ts`, `list.ts`, `download.ts` | 2–3 hours |
| Update CSP middleware, add server safety route | 30 min |
| Update existing tests, add new SW tests | 2–3 hours |
| Local dev verification (`dev-reset.sh`, run tests) | 1 hour |
| Cross-browser manual testing (Brave, Chrome, Firefox, Tor Browser) | 3–4 hours |
| Deploy to test.arkfile.net, verify with 2.3 GB ISO | 1 hour |
| Documentation update | 30 min |
| **Total** | **~2 days of focused work** |

---

## 16. Privacy Properties Summary (for security review)

- **No new network surface.** SW intercepts only same-origin synthetic URLs; makes no network requests itself. All chunk fetches use the existing `/api/...` endpoints over the user's existing connection (including Tor circuits for Tor Browser users).
- **No new persistent storage.** SW's `pendingStreams` Map is in-memory and lives only as long as the SW does. No IndexedDB, no caches.
- **No leak of filename or UUID.** The synthetic `/sw-download/<uuid>` URL is intercepted by the SW and never reaches the network. The filename in `Content-Disposition` is never seen by the network.
- **No fingerprinting addition.** Service Workers are a foundational web platform feature, not a fingerprinting vector. SW registration is invisible to the network observer.
- **Tor circuit usage unchanged.** The existing chunk fetches continue through the Tor circuit exactly as today; the SW only handles the local browser-side download pipeline.
- **No change to encryption boundaries.** The server still sees only ciphertext; the page still does all decryption client-side; the SW only forwards the already-decrypted byte stream within the browser to the download manager.

---

## 17. References

- StreamSaver.js: https://github.com/jimmywarting/StreamSaver.js (MIT) — canonical implementation of this pattern, used as a technique reference.
- W3C Service Workers spec: https://w3c.github.io/ServiceWorker/
- W3C Streams API spec: https://streams.spec.whatwg.org/
- Tor Browser security level documentation: https://tb-manual.torproject.org/security-settings/
- ProtonDrive uses this pattern for E2E encrypted file downloads (verifiable via DevTools on https://drive.proton.me).
- Cryptee uses this pattern: https://docs.crypt.ee/security/threat-model
- Chromium blob URL size investigation thread (linked from earlier failure analysis): https://bugs.chromium.org/p/chromium/issues/detail?id=375297

---

## 18. Open Questions for Implementation

These can be deferred but should be answered when the work is undertaken:

1. **SHA-256 verification timing:** verify-while-streaming via `TransformStream`, or skip in-browser verification and rely on the CLI for paranoid users? Recommendation: implement the streaming hash; it's small added code and provides post-download integrity assurance without UX cost.

2. **Progress reporting in the download manager:** Setting `Content-Length` on the SW Response gives the browser's download manager a progress bar. We have plaintext byte length from the metadata. Recommendation: include `Content-Length` in the SW Response.

3. **SW versioning strategy:** for a greenfield app, `skipWaiting`/`clients.claim` plus a hard reload after deploy is sufficient. For future production use, consider URL cache-busting (`/sw-download.js?v=<hash>`) and a UI prompt when a new SW activates.

4. **Cancel UX:** the current AbortController already exists; the SW path needs to wire it through. Recommendation: page sends `{ type: 'cancel', uuid }` to SW on user-initiated cancellation; SW cancels the stream; the download manager will show "interrupted."

5. **Multiple tabs:** if the same user has multiple tabs of Arkfile open, all share the same SW. UUIDs prevent collision. No cross-tab interference expected.
