# 06-frontend-supply-ops.md initial findings (partially completed)

## Slice F — finalized finding list (file:line evidence in hand)

Output: `docs/wip/review/06-frontend-supply-ops.md`

### Critical (3)

- **F-01: `X-Forwarded-For` localhost-gate bypass** — `c.RealIP()` is used at `handlers/middleware.go:303,536,562-563` and `handlers/bootstrap.go:35-39,106-110` for the admin/bootstrap localhost gate. `e.IPExtractor` is NEVER set in `main.go`. Echo default `c.RealIP()` walks `X-Forwarded-For`. Caddyfile.prod/test/local have no `trusted_proxies` directive (`Caddyfile.prod:9-46`), so Caddy appends rather than replaces. An attacker sending `X-Forwarded-For: 127.0.0.1` defeats both admin localhost gate AND bootstrap localhost gate. Confirms cross-refs A-02, A-13, A-14, A-26, E-14. **Critical / High confidence.**
- **F-02: Hardcoded dev-admin password + TOTP secret + fragile production detection** — `main.go:723-725` hardcodes `devAdminPassword="DevAdmin2025!SecureInitialPassword"` and `devAdminTOTPSecret="ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"`. Guard is `utils.IsProductionEnvironment()` (`utils/environment.go:11-24`) which is **env-var-fuzzy-match-only**: `ENVIRONMENT/NODE_ENV/GO_ENV/ENV` set to "production"/"prod", or hostname containing "prod"/"production"/"live", or PORT 443/80/8443. `scripts/prod-deploy.sh:276-413` writes `secrets.env` with `PORT=8080` and **no `ENVIRONMENT=production`**. Production safety depends entirely on whether the hostname happens to match a regex. Operator typo or VPS with neutral hostname → known admin credentials seeded. **Critical / High confidence.**
- **F-03: Bootstrap token harvested from journalctl** — `scripts/prod-deploy.sh:1186` instructs operator to grep journalctl for the bootstrap token. `systemd/arkfile.service` has no `StandardOutput=` / `StandardError=` directive that redacts. Anyone with root + journalctl access can re-bootstrap if the original admin hasn't consumed. Confirms cross-ref A-26. **High / High confidence.** (Upgrade to Critical if combined with F-01.)

### High (5)

- **F-04: WASM artifact has no SRI** — `client/static/index.html:355` loads `/js/libopaque.js` with no `integrity=` attribute. CSP `script-src 'self'` (`handlers/middleware.go:360`) protects against off-origin, but a same-origin cache/CDN/MITM substitution would land a tampered WASM blob. `libopaque.js` is checked in (`client/static/js/libopaque.js`, 345 KB) but not hash-pinned at serve time. **High / Medium confidence.**
- **F-05: Go binaries built without `-trimpath`, `-buildid=`, or `-ldflags='-s -w'`** — `scripts/setup/build.sh:417,421,425` uses `STATIC_LDFLAGS='-extldflags "-static"'` only. Result: embedded local paths in arkfile / arkfile-client / arkfile-admin (info leak), non-reproducible builds (no provenance), full debug symbol table. Also no release signing or SLSA attestation. **High / High confidence.**
- **F-06: libsodium is host-package, not pinned** — `.gitmodules` pins libopaque (6e9ac92) and liboprf (a8c0410) only. `scripts/setup/build.sh:409` uses `pkg-config --libs --static libsodium` against whatever apt/dnf installs. Crypto primitive supply chain depends on OS-level package state, not on the Arkfile repo. **High / High confidence.**
- **F-07: localStorage holds full JWT and refresh token** — `client/static/js/src/utils/auth.ts` uses `localStorage.setItem('token', ...)` and `localStorage.setItem('refresh_token', ...)`. XSS/dependency-compromise reads them. Direct confirmation of cross-ref A-05. **High / High confidence.**
- **F-08: `window.totpLoginData` holds password during TOTP window** — `client/static/js/src/auth/login.ts` and `auth/totp.ts` set `window.totpLoginData = { ..., password }`. Same-origin XSS reads the plaintext password. Direct confirmation of A-04. **High / High confidence.**

### Medium (~10)

- **F-09: systemd hardening gaps across all four units** — `arkfile.service`, `caddy.service`, `rqlite.service`, `seaweedfs.service` are all missing `LimitCORE=0`, `MemoryDenyWriteExecute=yes`, `LockPersonality=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectProc=invisible`, `ProcSubset=pid`, `CapabilityBoundingSet=`, `UMask=0077`, `IPAddressDeny=any` (with explicit allows). `arkfile.service` has `SystemCallFilter=@system-service` (good) but `rqlite.service` and `seaweedfs.service` do not. `LimitCORE=0` is the biggest gap — coredumps can dump OPAQUE / JWT signing / TOTP master keys to disk. Confirms A-18, B-25.
- **F-10: rqlite binds 0.0.0.0** — `systemd/rqlite.service:13-14` uses `-http-addr :4001 -raft-addr :4002`. Mitigated by firewall (`scripts/prod-deploy.sh:168-195` only allows ssh/http/https) but defense-in-depth gap if firewall is misconfigured/disabled. Should be `localhost:4001` / `localhost:4002`.
- **F-11: SeaweedFS integrity uses MD5** — `config/dependency-hashes.json:10-13` records `md5_url` for SeaweedFS release verification. MD5 is cryptographically broken. SHA-256 is provided by SeaweedFS releases too.
- **F-12: rqlite is "built from source" with no pinned commit** — `config/dependency-hashes.json:20`. The build script (`scripts/setup/06-setup-rqlite-build.sh`) presumably clones whatever tag/master is current at build time. Defer detailed read to a follow-up.
- **F-13: npm deps not pinned exact, no `--frozen-lockfile`** — `client/static/js/package.json:21-27` uses `^` ranges. `scripts/setup/build.sh:349` uses `bun install` without `--frozen-lockfile`. Even though `bun.lock` exists, drift is allowed.
- **F-14: CSP allows inline event handlers that the code uses** — `client/static/js/src/auth/totp.ts` emits `<button onclick="...">` and `<a href="#" onclick="...">` via `innerHTML`. CSP `script-src 'self' 'wasm-unsafe-eval'` has no `'unsafe-inline'`, so these inline handlers **silently do not fire** in production. Either dead UX or eventual pressure to loosen CSP. Flag for cleanup.
- **F-15: `style-src 'unsafe-inline'`** — `handlers/middleware.go:361`. Needed by `shared.html`'s `<style>` block (`client/static/shared.html:8-40`). Could be tightened by moving styles out to `/css/shared.css`.
- **F-16: No Permissions-Policy header** — `handlers/middleware.go:372-378` sets CSP / XCTO / XFO / XSSP / Referrer-Policy, but no `Permissions-Policy` (camera, microphone, geolocation, etc.).
- **F-17: No `require-trusted-types-for 'script'`** — same file. No Trusted Types defense for the ~15 `innerHTML` sinks identified across `client/static/js/src/**` (file-encryption flow, billing UI, contact-info UI, totp.ts, totp-setup.ts, share-list, password-modal, share modal, list.ts storage info).
- **F-18: TLS upstream uses `tls_insecure_skip_verify`** — `Caddyfile.prod:30`. Acceptable since both endpoints are on localhost with self-signed certs from setup/04-setup-tls-certs.sh, but flag as design choice that prevents the operator from ever swapping in real upstream certs without code changes.
- **F-19: `scripts/maintenance/rotate-jwt-keys.sh` may be stale code** — It manages files in `/opt/arkfile/etc/keys/jwt/current/` but Slice A noted that JWT signing keys are managed via `KeyManager` in the DB. Greenfield/AGENTS.md concern: deprecated maintenance script.

### Low / Informational (~7)

- **F-20: `/healthz` and `/readyz` publicly reachable via Caddy** — `main.go:32-65`. `/readyz` reports rqlite + storage status to anyone. Already E-22; cross-ref only.
- **F-21: `shared-init.js` uses `innerHTML` for error rendering** — `client/static/js/shared-init.js:10`. Currently hardcoded strings; refactor risk only.
- **F-22: `goose.go` sourcemaps available** — `scripts/setup/build.sh:18` enables `--sourcemap=external`. Production bundle ships with sourcemap files reachable from the same origin (info leak about minified code).
- **F-23: `tls_insecure_skip_verify` on Caddy upstream documented as intentional** — companion to F-18; informational.
- **F-24: deSEC token storage** — `scripts/prod-deploy.sh:548-552` writes `/var/lib/caddy/caddy-env` mode 0600 owned by caddy:caddy. Plaintext on disk. Acceptable for now; flag for future at-rest encryption design.
- **F-25: No `govulncheck` / `npm audit` / `bun audit` in build script** — informational hardening.
- **F-26: bun lockfile is text-format `bun.lock` (good)** — informational.

### Tables I'll populate

- 3.1 HTTP Security Header table per environment (local/test/prod) showing CSP / HSTS / XFO / XCTO / Permissions / Referrer.
- 3.2 systemd Hardening table per unit (arkfile / caddy / rqlite / seaweedfs) — directive present? value?
- 3.3 Supply Chain inventory — Go modules, npm packages, vendored C submodule pins, WASM artifact, lockfile state, integrity check (MD5 flag).
- 3.4 Frontend secret-adjacent storage matrix — localStorage / sessionStorage / window globals / cookies (with cross-refs to A-04/05/08, B-23, C-19).
- 3.5 CSP per environment (currently identical across all four Caddyfiles, since CSP is set by Go middleware — note this in the table).

### Open questions I'll list (developer to confirm)

1. File modes/owners on `/opt/arkfile/etc/**` at runtime (`.clinerules` blocks me; verified the scripts set 0600/0640/0700 but cannot read final state).
2. Whether `bun.lock` is committed (it is in the working tree as 1925 bytes per my earlier `ls`).
3. Whether the obsolete `scripts/maintenance/rotate-jwt-keys.sh` is intentionally kept or should be deleted (greenfield).
4. Confirm production deployments today set `ENVIRONMENT=production` somewhere outside `secrets.env` (systemd `Environment=`? `/etc/environment`?) — F-02 escalation hinges on this.
5. Whether release artifacts are signed today and how (cosign / minisign / pgp).

Estimated total: **~26 findings**.

---
