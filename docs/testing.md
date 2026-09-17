# TESTING

## Human Testing Protocol

### Test Scripts

Run from the repository root and stop immediately if any step fails.

Who runs what: scripts that change the deployment or read root-only deployment state (`dev-reset.sh`, `online-integrity-test.sh`) require `sudo`. Every other step runs as your regular user and refuses root. Developer-mode scripts write only under `/tmp/arkfile-*` directories owned by you (mode 700) and never into the repository. `/tmp/arkfile-e2e-test-data` is the single handoff between `e2e-test.sh`, `online-integrity-test.sh` (which only reads it), and `e2e-playwright.sh`; `dev-reset.sh` wipes it and `/tmp/arkfile-integrity-test-data` so every reset starts from clean test state. Playwright traces and screenshots land in `/tmp/arkfile-e2e-test-data/playwright/results` and are kept only when a run fails.

One-time setup for Playwright as your user: `bunx playwright install chromium` (needs network). If you previously ran `e2e-playwright.sh` with `sudo`, remove the root-owned leftovers once: `sudo rm -rf test-results playwright-report blob-report` in the repository and `sudo rm -f /usr/local/bin/bun /usr/local/bin/bunx`.

1. **All Go unit tests** (no sudo):

```bash
source scripts/setup/build-config.sh && \
export CGO_ENABLED=1 && \
export CGO_CFLAGS="$(cli_fido_cgo_cflags)" && \
export CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$PWD")" && \
export GOMAXPROCS="$(get_parallel_jobs)" && \
go test ./... -count=1
```

2. **Complete TypeScript checks** (type-check, builds, and unit tests; no sudo):

```bash
bash scripts/testing/test-typescript.sh
```

3. **Crypto benchmarks** (no sudo):

```bash
source scripts/setup/build-config.sh && \
export CGO_ENABLED=1 && \
export CGO_CFLAGS="$(cli_fido_cgo_cflags)" && \
export CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$PWD")" && \
export GOMAXPROCS="$(get_parallel_jobs)" && \
go test ./crypto -run '^$' \
  -bench 'Benchmark(Chunk|FEK|DeriveShareKey|ShareEnvelope)' \
  -benchmem -count=3
```

4. **Rebuild/reset the development deployment** (requires Bun 1.3.x already on the host; see `docs/setup.md`):

```bash
sudo bash scripts/dev-reset.sh
```

5. **Offline integrity test** (no sudo):

```bash
bash scripts/testing/offline-integrity-test.sh
```

6. **Primary CLI E2E test** (no sudo):

```bash
bash scripts/testing/e2e-test.sh
```

7. **Online integrity test** (sudo; reads `/tmp/arkfile-e2e-test-data` but does not modify it):

```bash
sudo bash scripts/testing/online-integrity-test.sh
```

8. **Playwright E2E test** (no sudo; same user as step 6):

```bash
bash scripts/testing/e2e-playwright.sh
```

The full reset-plus-test sequence for a local dev machine is `sudo bash fdre2e.sh`, which runs `dev-reset.sh` as root and then drops to your user for `e2e-test.sh` and `e2e-playwright.sh`.

### Manual Testing

Web App Browser TypeScript Frontend

1. Registration: OPAQUE and MFA (TOTP and/or HW Security Key)
2. Login with MFA
3. Upload file with Account password
4. Upload file with Custom password
5. List files
6. Tag files
7. Download Account-password-encrypted file, confirm sha256sum matches
7. Download Custom-password-encrypted file, confirm sha256sum matches
8. Share a file, download it from a separate private browser session
9. Revoke the share, and attempt to download it again
10. Export an .arkbackup of a file, use arkfile-client to decrypt locally, check tags
11. Attempt to upload and download a 2GB+ file on Brave (blob download, fallback method) 

Command-Line arkfile-client Go Utility

1. Registration: OPAQUE and MFA (TOTP and/or HW Security Key)
2. Login with MFA
3. Upload file with Account password
4. Upload file with Custom password
5. List files
6. Tag files
7. Download Account-password-encrypted file, confirm sha256sum matches
7. Download Custom-password-encrypted file, confirm sha256sum matches
8. Share a file, download it from a separate private browser session
9. Revoke the share, and attempt to download it again
10. Export an .arkbackup of a file, use arkfile-client to decrypt locally, check tags
