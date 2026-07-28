#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_ROOT=""
FUZZ_TIME="${ARKFILE_INTEGRITY_FUZZ_TIME:-2s}"
FUZZ_COMMAND_TIMEOUT="${ARKFILE_INTEGRITY_FUZZ_COMMAND_TIMEOUT:-90s}"
SELECTED_GROUP="${1:-all}"
TESTS_RUN=0
TESTS_PASSED=0

log_info() {
    printf '[INFO] %s\n' "$1"
}

log_ok() {
    printf '[OK] %s\n' "$1"
}

log_error() {
    printf '[X] %s\n' "$1" >&2
}

cleanup() {
    if [ -n "$TEST_ROOT" ] && [ -d "$TEST_ROOT" ]; then
        rm -rf "$TEST_ROOT"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    printf 'Usage: %s [all|conformance|parsers|fuzz|state|race|analyzers|production]\n' "$0"
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
        return 1
    fi
}

require_file() {
    if [ ! -f "$1" ]; then
        log_error "Required local build artifact not found: $1"
        return 1
    fi
}

preflight() {
    cd "$PROJECT_ROOT" || return 1

    case "$SELECTED_GROUP" in
        all|conformance|parsers|fuzz|state|race|analyzers|production) ;;
        help|-h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            log_error "Unknown integrity group: $SELECTED_GROUP"
            return 1
            ;;
    esac

    require_command go || return 1
    if [ "$SELECTED_GROUP" = "all" ] || [ "$SELECTED_GROUP" = "conformance" ] || [ "$SELECTED_GROUP" = "parsers" ] || [ "$SELECTED_GROUP" = "production" ]; then
        require_command bun || return 1
    fi
    if [ "$SELECTED_GROUP" = "all" ] || [ "$SELECTED_GROUP" = "fuzz" ]; then
        require_command timeout || return 1
    fi
    require_command grep || return 1
    require_file "$PROJECT_ROOT/go.mod" || return 1
    if [ "$SELECTED_GROUP" = "all" ] || [ "$SELECTED_GROUP" = "conformance" ] || [ "$SELECTED_GROUP" = "fuzz" ]; then
        require_file "$PROJECT_ROOT/crypto/testdata/crypto-conformance-v2.json" || return 1
    fi

    source "$PROJECT_ROOT/scripts/setup/build-config.sh"
    init_fido_paths

    require_file "$PROJECT_ROOT/$LIBOPAQUE_A" || return 1
    require_file "$PROJECT_ROOT/$LIBOPRF_A" || return 1
    require_file "$PROJECT_ROOT/$LIBSODIUM_A" || return 1
    require_file "$FIDO_PREFIX/lib/libfido2.a" || return 1
    require_file "$FIDO_PREFIX/lib/libcbor.a" || return 1

    export CGO_ENABLED=1
    export CGO_CFLAGS
    export CGO_LDFLAGS
    CGO_CFLAGS="$(cli_fido_cgo_cflags)"
    CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$PROJECT_ROOT")"

    # Cap Go/fuzz workers at half of online CPUs (minimum 1).
    export GOMAXPROCS
    GOMAXPROCS="$(get_parallel_jobs)"

    TEST_ROOT="$(mktemp -d /tmp/arkfile-offline-integrity.XXXXXX)" || return 1
    log_ok "Offline integrity preflight passed (GOMAXPROCS=$GOMAXPROCS)"
}

run_group() {
    local name="$1"
    local function_name="$2"

    if [ "$SELECTED_GROUP" != "all" ] && [ "$SELECTED_GROUP" != "$name" ]; then
        return 0
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    printf '\n[RUN] %s\n' "$name"
    if "$function_name"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_ok "$name"
    else
        log_error "$name"
    fi
}

run_conformance() {
    go test ./crypto -run '^(TestBuildChunkAAD_CrossLanguageVector|TestAADSharedFixture|TestPasswordKDFConformance|TestAESGCMSharedFixture|TestOwnerEnvelopeSharedFixtureDecrypt|TestShareEnvelopeSharedFixture(Decrypt|RejectsTampering)|TestArgon2ConformanceFixture)$' -count=1 || return 1
    (
        cd client/static/js || exit 1
        bun test \
            src/__tests__/aad.test.ts \
            src/__tests__/argon2-conformance.test.ts \
            src/__tests__/aes-gcm-conformance.test.ts \
            src/__tests__/aes-gcm.test.ts \
            src/__tests__/file-encryption.test.ts \
            src/__tests__/metadata-helpers.test.ts \
            src/__tests__/owner-envelope.test.ts \
            src/__tests__/share-envelope-conformance.test.ts
    )
}

run_parser_regressions() {
    go test ./crypto ./cmd/arkfile-client \
        -run '^(TestParsePasswordEnvelopeErrors|TestDeriveShareKey_InvalidSalt(Length|Encoding)|TestIssueShareTicket_RejectsBadInputs|TestVerifyShareTicket_Rejects(Malformed|WrongEntityID|WrongShareID|Expired|FutureIssuedAt|TamperedTicket|WrongKey)|TestParseShareEnvelope_(MissingFEK|MissingDownloadToken|InvalidJSON)|TestParseBundle_(InvalidMagic|InvalidVersion|InvalidJSON|TruncatedFile|NonexistentFile|HeaderTooLarge)|TestDecryptBlobCommand_RejectsBundleMissingOwnerUsername|TestReadAccountKeyFromFileRejectsBroadPermissions)$' \
        -count=1 || return 1
    (
        cd client/static/js || exit 1
        bun test src/__tests__/metadata-helpers.test.ts src/__tests__/owner-envelope.test.ts src/__tests__/share-crypto.test.ts
    )
}

run_short_fuzzing() {
    timeout "$FUZZ_COMMAND_TIMEOUT" go test ./crypto -run '^$' -fuzz '^FuzzParseFEKEnvelopeHeader$' -fuzztime="$FUZZ_TIME" || return 1
    timeout "$FUZZ_COMMAND_TIMEOUT" go test ./crypto -run '^$' -fuzz '^FuzzParseShareEnvelope$' -fuzztime="$FUZZ_TIME" || return 1
    timeout "$FUZZ_COMMAND_TIMEOUT" go test ./crypto -run '^$' -fuzz '^FuzzVerifyShareTicket$' -fuzztime="$FUZZ_TIME" || return 1
    timeout "$FUZZ_COMMAND_TIMEOUT" go test ./cmd/arkfile-client -run '^$' -fuzz '^FuzzParseBundle$' -fuzztime="$FUZZ_TIME"
}

run_state_invariants() {
    go test ./handlers \
        -run '^(TestClaimUploadCompletionIsSingleWinner|TestReleaseUploadCompletionClaimOnlyReopensCompletingState|TestDownloadShareChunk_AtomicDoubleSpendBlocked|TestDownloadShareChunk_AtomicConditionalFailure|TestBTCPayWebhookHandler_ConcurrentDeliveryCreditsOnce)$' \
        -count=1 || return 1
    go test ./logging -run '^TestSecurityEventSensitiveDataExclusion$' -count=1
}

run_race_invariants() {
    go test -race ./handlers ./billing \
        -run '^(TestClaimUploadCompletionIsSingleWinner|TestReleaseUploadCompletionClaimOnlyReopensCompletingState|TestDownloadShareChunk_AtomicDoubleSpendBlocked|TestDownloadShareChunk_AtomicConditionalFailure|TestBTCPayWebhookHandler_ConcurrentDeliveryCreditsOnce|TestProcessSubscriptionBridgeCallback_ConcurrentIdempotency)$' \
        -count=1
}

run_analyzers() {
    go test ./internal/analysis/arkfilechecks ./cmd/arkfile-analyzers -count=1 || return 1
    go run ./cmd/arkfile-analyzers ./...
}

expect_wasm_build_rejection() {
    local label="$1"
    shift
    local output="$TEST_ROOT/${label}.log"

    if env "$@" bash scripts/setup/build-libopaque-wasm.sh >"$output" 2>&1; then
        log_error "WASM build accepted forbidden profile: $label"
        return 1
    fi
    log_ok "WASM build rejected forbidden profile: $label"
}

run_production_profiles() {
    go test ./config ./utils -run 'Production|IsProduction' -count=1 || return 1
    bash scripts/testing/test-typescript.sh build || return 1

    expect_wasm_build_rejection norandom \
        LIBOPAQUE_DEFINES=-DNORANDOM \
        ARKFILE_ALLOW_WASM_TRACE=true || return 1
    expect_wasm_build_rejection unapproved-trace \
        LIBOPAQUE_DEFINES=-DTRACE \
        ARKFILE_ALLOW_WASM_TRACE=false || return 1

    local production_script
    for production_script in \
        scripts/local-deploy.sh \
        scripts/local-update.sh \
        scripts/setup/vps-first-deploy.sh \
        scripts/setup/vps-update.sh; do
        if ! grep -Eq '^[[:space:]]*unset LIBOPAQUE_DEFINES' "$production_script"; then
            log_error "Production-like script does not clear LIBOPAQUE_DEFINES: $production_script"
            return 1
        fi
        if grep -Eq 'ARKFILE_ALLOW_WASM_TRACE[[:space:]]*=[[:space:]]*true' "$production_script"; then
            log_error "Production-like script enables WASM trace permission: $production_script"
            return 1
        fi
    done
}

main() {
    if ! preflight; then
        exit 1
    fi

    run_group conformance run_conformance
    run_group parsers run_parser_regressions
    run_group fuzz run_short_fuzzing
    run_group state run_state_invariants
    run_group race run_race_invariants
    run_group analyzers run_analyzers
    run_group production run_production_profiles

    printf '\n[STATS] Offline integrity results\n'
    printf 'Groups run:    %d\n' "$TESTS_RUN"
    printf 'Groups passed: %d\n' "$TESTS_PASSED"
    printf 'Groups failed: %d\n' "$((TESTS_RUN - TESTS_PASSED))"

    if [ "$TESTS_RUN" -eq "$TESTS_PASSED" ]; then
        log_ok "All selected offline integrity groups passed"
        exit 0
    fi
    exit 1
}

main "$@"
