# TESTING

## Human Testing Protocol

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
