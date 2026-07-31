# TESTING

## Human Testing Protocol

### Test Scripts

Run from the repository root and stop immediately if any step fails.

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

4. **Rebuild/reset the development deployment**:

```bash
sudo bash scripts/dev-reset.sh
```

5. **Offline integrity test**:

```bash
bash scripts/testing/offline-integrity-test.sh
```

6. **Primary CLI E2E test**:

```bash
bash scripts/testing/e2e-test.sh
```

7. **Online integrity test**:

```bash
sudo bash scripts/testing/online-integrity-test.sh
```

8. **Playwright E2E test**:

```bash
sudo bash scripts/testing/e2e-playwright.sh
```

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
