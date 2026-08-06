#!/bin/bash

# Run after scripts/testing/e2e-test.sh:
# sudo bash scripts/testing/online-integrity-test.sh

set -uo pipefail

SERVER_URL="${SERVER_URL:-https://localhost:8443}"
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
ADMIN_TOTP_SECRET="${ADMIN_TOTP_SECRET:-ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D}"
CLIENT="/opt/arkfile/bin/arkfile-client"
ADMIN="/opt/arkfile/bin/arkfile-admin"
TEST_ROOT="/tmp/arkfile-integrity-test-data"
STORAGE_ROOT="/opt/arkfile/var/lib/seaweedfs/data"
APP_LOG_ROOT="/opt/arkfile/logs"
SECRETS_FILE="/opt/arkfile/etc/secrets.env"
E2E_USERNAME="arkfile-dev-test-user"
E2E_MFA_SECRET="/tmp/arkfile-e2e-test-data/mfa-secret"
MAX_RSS_KB="${ARKFILE_CLI_MAX_RSS_KB:-262144}"
MAX_RSS_GROWTH_KB="${ARKFILE_CLI_MAX_RSS_GROWTH_KB:-98304}"
SKIP_RESOURCES="${ARKFILE_INTEGRITY_SKIP_RESOURCES:-false}"
SKIP_RACES="${ARKFILE_INTEGRITY_SKIP_RACES:-false}"

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
INTEGRITY_USERNAME="integrity-${RUN_ID}"
ACCOUNT_PASSWORD="IntegrityAccount-${RUN_ID}-Password!"
CUSTOM_PASSWORD="IntegrityCustom-${RUN_ID}-Password!"
SHARE_PASSWORD="IntegrityShare-${RUN_ID}-Password!"
PLAINTEXT_FRAGMENT="arkfile-plaintext-fragment-${RUN_ID}"
FILENAME_MARKER="integrity-filename-${RUN_ID}.bin"
CUSTOM_FILENAME_MARKER="integrity-custom-${RUN_ID}.bin"
PASSWORD_HINT="integrity-hint-${RUN_ID}"
ACCOUNT_FILE_ID=""
CUSTOM_FILE_ID=""
RESOURCE_FILE_ID=""
ADMIN_READY=false
USER_CREATED=false
TESTS_RUN=0
TESTS_PASSED=0
CANARY_FILE=""
TEST_ROOT_READY=false

log_info() {
    printf '[INFO] %s\n' "$1"
}

log_ok() {
    printf '[OK] %s\n' "$1"
}

log_error() {
    printf '[X] %s\n' "$1" >&2
}

stop_agent() {
    if [ "$TEST_ROOT_READY" != true ]; then
        return
    fi
    HOME="$TEST_ROOT/home" "$CLIENT" agent stop >/dev/null 2>&1 || true
}

cleanup_user() {
    if [ "$ADMIN_READY" != true ] || [ "$USER_CREATED" != true ]; then
        return 0
    fi
    local failed=0
    HOME="$TEST_ROOT/home" "$ADMIN" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        delete-user --username "$INTEGRITY_USERNAME" --confirm >/dev/null 2>&1 || {
        log_error "Could not remove dedicated integrity user $INTEGRITY_USERNAME"
        failed=1
    }

    local admin_token
    admin_token="$(jq -r '.access_token // empty' "$TEST_ROOT/home/.arkfile-admin-session.json" 2>/dev/null)"
    if [ -n "$admin_token" ]; then
        curl -skf -X POST \
            -H "Authorization: Bearer $admin_token" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$INTEGRITY_USERNAME\",\"confirm\":true}" \
            "$SERVER_URL/api/admin/dev-test/users/cleanup" >/dev/null 2>&1 || {
            log_error "Could not hard-delete dedicated integrity user through the development cleanup API"
            failed=1
        }
    else
        log_error "Admin session token unavailable for development cleanup API"
        failed=1
    fi
    if [ "$failed" -eq 0 ]; then
        USER_CREATED=false
    fi
    return "$failed"
}

cleanup() {
    stop_agent
    cleanup_user
    if [ "$TEST_ROOT_READY" = true ]; then
        rm -rf "$TEST_ROOT"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
        return 1
    fi
}

require_file() {
    if [ ! -f "$1" ]; then
        log_error "Required file not found: $1"
        return 1
    fi
}

preflight() {
    require_command curl || return 1
    require_command jq || return 1
    require_command grep || return 1
    require_command flock || return 1
    require_command sha256sum || return 1
    require_command timeout || return 1
    require_command /usr/bin/time || return 1
    require_file "$CLIENT" || return 1
    require_file "$ADMIN" || return 1

    if [ "$(id -u)" -ne 0 ]; then
        log_error "Online integrity must run as root."
        log_error "Run: sudo bash scripts/testing/online-integrity-test.sh"
        return 1
    fi
    if ! test -f "$SECRETS_FILE"; then
        log_error "Required deployment configuration not found: $SECRETS_FILE"
        return 1
    fi

    exec 9>/tmp/arkfile-integrity-test.lock
    if ! flock -n 9; then
        log_error "Another online integrity run holds /tmp/arkfile-integrity-test.lock"
        return 1
    fi

    if ! curl -skf "$SERVER_URL/readyz" | jq -e '.status == "ready"' >/dev/null 2>&1; then
        log_error "Live Arkfile development deployment is not healthy at $SERVER_URL"
        log_error "Run the appropriate development reset manually before this script."
        return 1
    fi

    local dev_api_enabled
    dev_api_enabled="$(awk -F= '$1 == "ADMIN_DEV_TEST_API_ENABLED" {print $2}' "$SECRETS_FILE" | tr -d '\r')"
    if [ "$dev_api_enabled" != "true" ]; then
        log_error "ADMIN_DEV_TEST_API_ENABLED=true is required"
        return 1
    fi

    rm -rf "$TEST_ROOT"
    install -d -m 700 "$TEST_ROOT" "$TEST_ROOT/home" "$TEST_ROOT/baseline" "$TEST_ROOT/post" "$TEST_ROOT/delta" "$TEST_ROOT/files"
    TEST_ROOT_READY=true
    export HOME="$TEST_ROOT/home"
    export XDG_RUNTIME_DIR="$TEST_ROOT/runtime"
    install -d -m 700 "$XDG_RUNTIME_DIR"

    CANARY_FILE="$TEST_ROOT/canaries.tsv"
    {
        printf 'account_password\t%s\n' "$ACCOUNT_PASSWORD"
        printf 'custom_password\t%s\n' "$CUSTOM_PASSWORD"
        printf 'share_password\t%s\n' "$SHARE_PASSWORD"
        printf 'plaintext_filename\t%s\n' "$FILENAME_MARKER"
        printf 'custom_plaintext_filename\t%s\n' "$CUSTOM_FILENAME_MARKER"
        printf 'plaintext_fragment\t%s\n' "$PLAINTEXT_FRAGMENT"
        printf 'password_hint\t%s\n' "$PASSWORD_HINT"
    } >"$CANARY_FILE"
    chmod 600 "$CANARY_FILE"

    log_ok "Online integrity preflight passed"
}

wait_for_fresh_totp_window() {
    local remaining
    remaining=$((31 - $(date +%s) % 30))
    log_info "Waiting ${remaining}s for a fresh admin TOTP window"
    sleep "$remaining"
}

admin_login() {
    wait_for_fresh_totp_window
    local totp_code output
    totp_code="$("$CLIENT" generate-totp --secret "$ADMIN_TOTP_SECRET" 2>/dev/null)"
    if [ -z "$totp_code" ]; then
        log_error "Could not generate admin TOTP code"
        return 1
    fi
    if ! output="$(printf '%s\n' "$ADMIN_PASSWORD" | "$ADMIN" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        --username "$ADMIN_USERNAME" \
        login \
        --password-stdin \
        --totp-code "$totp_code" \
        --save-session 2>&1)"; then
        log_error "Admin login failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    ADMIN_READY=true
    log_ok "Dedicated admin session established"
}

capture_preserved_e2e_state() {
    if [ ! -s "$E2E_MFA_SECRET" ]; then
        log_error "Required post-E2E MFA state is missing: $E2E_MFA_SECRET"
        return 1
    fi
    sha256sum "$E2E_MFA_SECRET" | awk '{print $1}' >"$TEST_ROOT/baseline/e2e-mfa.sha256"

    if ! "$ADMIN" --server-url "$SERVER_URL" --tls-insecure \
        user-status --username "$E2E_USERNAME" >"$TEST_ROOT/baseline/e2e-user-status.txt"; then
        log_error "Could not read the E2E user state"
        return 1
    fi
    if ! grep -Eq '^Exists:[[:space:]]+Yes$' "$TEST_ROOT/baseline/e2e-user-status.txt" ||
        ! grep -Eq '^Approved:[[:space:]]+Yes$' "$TEST_ROOT/baseline/e2e-user-status.txt"; then
        log_error "The required approved E2E user state is not present"
        return 1
    fi

    if ! "$ADMIN" --server-url "$SERVER_URL" --tls-insecure \
        get-approval-policy --json >"$TEST_ROOT/baseline/approval-policy.json"; then
        log_error "Could not read the post-E2E approval policy"
        return 1
    fi
    if ! jq -e '.require_approval == false' "$TEST_ROOT/baseline/approval-policy.json" >/dev/null; then
        log_error "Online integrity requires the post-E2E auto-approval state"
        return 1
    fi
    log_ok "Captured E2E and Playwright preservation state"
}

verify_preserved_e2e_state() {
    local current_mfa_hash
    if [ ! -s "$E2E_MFA_SECRET" ]; then
        log_error "E2E MFA state was removed during online integrity"
        return 1
    fi
    current_mfa_hash="$(sha256sum "$E2E_MFA_SECRET" | awk '{print $1}')"
    if [ "$current_mfa_hash" != "$(<"$TEST_ROOT/baseline/e2e-mfa.sha256")" ]; then
        log_error "E2E MFA state changed during online integrity"
        return 1
    fi

    if ! "$ADMIN" --server-url "$SERVER_URL" --tls-insecure \
        user-status --username "$E2E_USERNAME" >"$TEST_ROOT/post/e2e-user-status.txt"; then
        log_error "Could not re-read the E2E user state"
        return 1
    fi
    if ! grep -Eq '^Exists:[[:space:]]+Yes$' "$TEST_ROOT/post/e2e-user-status.txt" ||
        ! grep -Eq '^Approved:[[:space:]]+Yes$' "$TEST_ROOT/post/e2e-user-status.txt"; then
        log_error "E2E user approval state changed during online integrity"
        return 1
    fi

    if ! "$ADMIN" --server-url "$SERVER_URL" --tls-insecure \
        get-approval-policy --json >"$TEST_ROOT/post/approval-policy.json"; then
        log_error "Could not re-read the approval policy"
        return 1
    fi
    if ! jq -e '.require_approval == false' "$TEST_ROOT/post/approval-policy.json" >/dev/null; then
        log_error "Auto-approval state changed during online integrity"
        return 1
    fi
    log_ok "E2E and Playwright state remained intact"
}

snapshot_tree() {
    local root="$1"
    local output="$2"
    if ! test -d "$root"; then
        : >"$output"
        return
    fi
    find "$root" -type f -printf '%p\t%s\t%T@\n' 2>/dev/null | sort >"$output"
}

snapshot_arkfile_temp() {
    local output="$1"
    local root
    {
        for root in /tmp/systemd-private-*-arkfile.service-*/tmp /var/tmp/systemd-private-*-arkfile.service-*/tmp; do
            test -d "$root" || continue
            find "$root" -type f -printf '%p\t%s\t%T@\n' 2>/dev/null
        done
    } | sort >"$output"
}

capture_database() {
    local output="$1"
    local username password address
    username="$(awk -F= '$1 == "RQLITE_USERNAME" {print substr($0, index($0, "=") + 1)}' "$SECRETS_FILE")"
    password="$(awk -F= '$1 == "RQLITE_PASSWORD" {print substr($0, index($0, "=") + 1)}' "$SECRETS_FILE")"
    address="$(awk -F= '$1 == "RQLITE_ADDRESS" {print substr($0, index($0, "=") + 1)}' "$SECRETS_FILE")"
    if [ -z "$username" ] || [ -z "$password" ] || [ -z "$address" ]; then
        log_error "Could not load rqlite inspection configuration"
        return 1
    fi

    local config="$TEST_ROOT/rqlite-curl.conf"
    {
        printf 'silent\n'
        printf 'show-error\n'
        printf 'fail\n'
        printf 'user = "%s:%s"\n' "$username" "$password"
        printf 'url = "%s/db/backup?fmt=sql"\n' "$address"
    } >"$config"
    chmod 600 "$config"
    curl --config "$config" >"$output" || return 1
    if ! grep -Eq 'CREATE TABLE|BEGIN TRANSACTION|PRAGMA' "$output"; then
        log_error "rqlite backup did not return a SQL snapshot"
        return 1
    fi
}

capture_journal_cursor() {
    journalctl -u arkfile -n 1 --show-cursor --no-pager 2>/dev/null |
        awk '/^-- cursor: / {sub("^-- cursor: ", ""); print; exit}'
}

capture_baseline() {
    capture_database "$TEST_ROOT/baseline/database.sql" || return 1
    capture_journal_cursor >"$TEST_ROOT/baseline/journal.cursor"
    if [ ! -s "$TEST_ROOT/baseline/journal.cursor" ]; then
        log_error "Could not capture arkfile journal cursor"
        return 1
    fi
    snapshot_arkfile_temp "$TEST_ROOT/baseline/tmp.tsv"
    snapshot_tree "$STORAGE_ROOT" "$TEST_ROOT/baseline/storage.tsv"
    snapshot_tree "$APP_LOG_ROOT" "$TEST_ROOT/baseline/logs.tsv"
    log_ok "Captured server-side baseline"
}

create_plaintext_fixtures() {
    local account_file="$TEST_ROOT/files/$FILENAME_MARKER"
    local custom_file="$TEST_ROOT/files/$CUSTOM_FILENAME_MARKER"

    printf '%s\n' "$PLAINTEXT_FRAGMENT" >"$account_file"
    dd if=/dev/urandom bs=1M count=1 status=none >>"$account_file"
    printf '%s\n' "${PLAINTEXT_FRAGMENT}-custom" >"$custom_file"
    dd if=/dev/urandom bs=1M count=1 status=none >>"$custom_file"
    chmod 600 "$account_file" "$custom_file"

    printf 'plaintext_digest\t%s\n' "$(sha256sum "$account_file" | awk '{print $1}')" >>"$CANARY_FILE"
    printf 'custom_plaintext_digest\t%s\n' "$(sha256sum "$custom_file" | awk '{print $1}')" >>"$CANARY_FILE"
}

register_integrity_user() {
    local output
    USER_CREATED=true
    if ! output="$(printf '%s\n%s\n' "$ACCOUNT_PASSWORD" "$ACCOUNT_PASSWORD" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        register \
        --password-stdin \
        --username "$INTEGRITY_USERNAME" 2>&1)"; then
        log_error "Dedicated integrity user registration failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    if ! output="$("$CLIENT" --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --show-secret 2>&1)"; then
        log_error "Integrity user TOTP setup failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    local secret code
    secret="$(printf '%s\n' "$output" | awk -F: '/TOTP_SECRET:/ {gsub(/ /, "", $2); print $2; exit}')"
    if [ -z "$secret" ]; then
        log_error "Integrity user TOTP secret was not returned"
        return 1
    fi
    printf 'totp_secret\t%s\n' "$secret" >>"$CANARY_FILE"
    printf '%s\n' "$secret" >"$TEST_ROOT/user-totp-secret"
    chmod 600 "$TEST_ROOT/user-totp-secret"
    code="$("$CLIENT" generate-totp --secret "$secret" 2>/dev/null)"
    if ! "$CLIENT" --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --verify "$code" >/dev/null; then
        log_error "Integrity user TOTP verification failed"
        return 1
    fi

    if ! "$ADMIN" --server-url "$SERVER_URL" --tls-insecure \
        set-storage --username "$INTEGRITY_USERNAME" --limit "500MB" >/dev/null; then
        log_error "Integrity user storage allocation failed"
        return 1
    fi

    wait_for_fresh_totp_window
    local login_code
    login_code="$("$CLIENT" generate-totp --secret "$secret" 2>/dev/null)"
    if [ -z "$login_code" ]; then
        log_error "Could not generate integrity user TOTP code"
        return 1
    fi
    if ! output="$(printf '%s\n' "$ACCOUNT_PASSWORD" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        --username "$INTEGRITY_USERNAME" \
        login \
        --password-stdin \
        --totp-code "$login_code" \
        --save-session \
        --cache-key 2>&1)"; then
        log_error "Integrity user login failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    log_ok "Dedicated integrity user created and authenticated"
}

extract_file_id() {
    printf '%s\n' "$1" | grep -Eo 'file_id=[^ )]+' | awk -F= 'NR == 1 {print $2}'
}

run_canary_flows() {
    create_plaintext_fixtures || return 1
    register_integrity_user || return 1

    local account_file="$TEST_ROOT/files/$FILENAME_MARKER"
    local custom_file="$TEST_ROOT/files/$CUSTOM_FILENAME_MARKER"
    local output

    if ! output="$("$CLIENT" --server-url "$SERVER_URL" --tls-insecure upload \
        --file "$account_file" --password-type account 2>&1)"; then
        log_error "Account-password canary upload failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    ACCOUNT_FILE_ID="$(extract_file_id "$output")"
    if [ -z "$ACCOUNT_FILE_ID" ]; then
        log_error "Account-password canary upload did not return a file ID"
        return 1
    fi

    if ! "$CLIENT" --server-url "$SERVER_URL" --tls-insecure download \
        --file-id "$ACCOUNT_FILE_ID" --output "$TEST_ROOT/account-download.bin" >/dev/null; then
        log_error "Account-password canary download failed"
        return 1
    fi
    if ! cmp -s "$account_file" "$TEST_ROOT/account-download.bin"; then
        log_error "Account-password canary round trip changed plaintext"
        return 1
    fi

    if ! "$CLIENT" --server-url "$SERVER_URL" --tls-insecure export \
        --file-id "$ACCOUNT_FILE_ID" --output "$TEST_ROOT/account.arkbackup" >/dev/null; then
        log_error "Canary backup export failed"
        return 1
    fi
    if ! printf '%s\n' "$ACCOUNT_PASSWORD" | "$CLIENT" decrypt-blob \
        --bundle "$TEST_ROOT/account.arkbackup" \
        --password-stdin \
        --output "$TEST_ROOT/account-offline.bin" >/dev/null; then
        log_error "Canary backup offline decryption failed"
        return 1
    fi
    if ! cmp -s "$account_file" "$TEST_ROOT/account-offline.bin"; then
        log_error "Canary backup round trip changed plaintext"
        return 1
    fi

    if ! output="$(printf '%s\n' "$CUSTOM_PASSWORD" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --password-stdin \
        --file "$custom_file" \
        --password-type custom \
        --hint "$PASSWORD_HINT" 2>&1)"; then
        log_error "Custom-password canary upload failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    CUSTOM_FILE_ID="$(extract_file_id "$output")"
    if [ -z "$CUSTOM_FILE_ID" ]; then
        log_error "Custom-password canary upload did not return a file ID"
        return 1
    fi
    if ! printf '%s\n' "$CUSTOM_PASSWORD" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download \
        --password-stdin \
        --file-id "$CUSTOM_FILE_ID" \
        --output "$TEST_ROOT/custom-download.bin" >/dev/null; then
        log_error "Custom-password canary download failed"
        return 1
    fi
    if ! cmp -s "$custom_file" "$TEST_ROOT/custom-download.bin"; then
        log_error "Custom-password canary round trip changed plaintext"
        return 1
    fi

    if ! output="$(printf '%s\n' "$SHARE_PASSWORD" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        share create \
        --password-stdin \
        --file-id "$ACCOUNT_FILE_ID" \
        --expires 0 2>&1)"; then
        log_error "Canary share creation failed"
        printf '%s\n' "$output" >&2
        return 1
    fi
    local share_id
    share_id="$(printf '%s\n' "$output" | awk '/Share ID:/ {print $3; exit}')"
    if [ -z "$share_id" ]; then
        log_error "Canary share creation did not return a share ID"
        return 1
    fi
    if ! printf '%s\n' "$SHARE_PASSWORD" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        share download \
        --password-stdin \
        --share-id "$share_id" \
        --output "$TEST_ROOT/share-download.bin" >/dev/null; then
        log_error "Canary share download failed"
        return 1
    fi
    if ! cmp -s "$account_file" "$TEST_ROOT/share-download.bin"; then
        log_error "Canary share round trip changed plaintext"
        return 1
    fi

    log_ok "Privacy canary flows completed"
}

measure_command_rss() {
    local label="$1"
    local command_output="$2"
    shift 2
    local time_file="$TEST_ROOT/${label}.time"

    if ! /usr/bin/time -v -o "$time_file" "$@" >"$command_output" 2>&1; then
        return 1
    fi
    awk -F: '/Maximum resident set size/ {gsub(/^[ \t]+/, "", $2); print $2; exit}' "$time_file"
}

assert_memory_bounds() {
    local measurements_file="$1"
    local maximum minimum growth
    maximum="$(awk 'NR == 1 || $2 > max {max=$2} END {print max+0}' "$measurements_file")"
    minimum="$(awk 'NR == 1 || $2 < min {min=$2} END {print min+0}' "$measurements_file")"
    growth=$((maximum - minimum))

    if [ "$maximum" -gt "$MAX_RSS_KB" ]; then
        log_error "CLI maximum RSS ${maximum} KiB exceeds ${MAX_RSS_KB} KiB ceiling"
        return 1
    fi
    if [ "$growth" -gt "$MAX_RSS_GROWTH_KB" ]; then
        log_error "CLI RSS growth ${growth} KiB exceeds ${MAX_RSS_GROWTH_KB} KiB ceiling"
        return 1
    fi
    log_info "CLI RSS range: ${minimum}-${maximum} KiB; growth ${growth} KiB"
}

run_resource_measurements() {
    local measurements="$TEST_ROOT/resource-rss.tsv"
    : >"$measurements"
    local sizes=(1048576 20971520 50000000 100000000)
    local size file output file_id upload_rss download_rss

    for size in "${sizes[@]}"; do
        if [ "$size" -gt 100000000 ]; then
            log_error "Resource payload exceeds the 100 MB approval boundary: $size"
            return 1
        fi
        file="$TEST_ROOT/files/resource-${size}.bin"
        "$CLIENT" generate-test-file --filename "$file" --size "$size" --pattern random >/dev/null || return 1

        local upload_output="$TEST_ROOT/upload-${size}.out"
        upload_rss="$(measure_command_rss "upload-${size}" "$upload_output" "$CLIENT" \
            --server-url "$SERVER_URL" \
            --tls-insecure \
            upload \
            --file "$file" \
            --password-type account)" || return 1
        output="$(<"$upload_output")"
        file_id="$(extract_file_id "$output")"
        if [ -z "$file_id" ]; then
            log_error "Resource upload did not return a file ID for $size bytes"
            return 1
        fi
        RESOURCE_FILE_ID="$file_id"
        printf 'upload-%s\t%s\n' "$size" "$upload_rss" >>"$measurements"

        download_rss="$(measure_command_rss "download-${size}" "$TEST_ROOT/download-${size}.out" "$CLIENT" \
            --server-url "$SERVER_URL" \
            --tls-insecure \
            download \
            --file-id "$file_id" \
            --output "$TEST_ROOT/resource-download-${size}.bin")" || return 1
        printf 'download-%s\t%s\n' "$size" "$download_rss" >>"$measurements"
        if ! cmp -s "$file" "$TEST_ROOT/resource-download-${size}.bin"; then
            log_error "Resource round trip failed for $size bytes"
            return 1
        fi
        rm -f "$TEST_ROOT/resource-download-${size}.bin"
    done

    assert_memory_bounds "$measurements" || return 1
    log_ok "CLI streaming memory remained within the documented ceiling and growth bound"
}

run_interruption_checks() {
    if [ -z "$RESOURCE_FILE_ID" ]; then
        log_error "Interruption checks require the resource measurement file"
        return 1
    fi

    local partial="$TEST_ROOT/interrupted-download.bin"
    if timeout -s INT 0.2s "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download \
        --file-id "$RESOURCE_FILE_ID" \
        --output "$partial" >/dev/null 2>&1; then
        log_error "Download completed before interruption could be exercised"
        return 1
    fi
    if [ -s "$partial" ]; then
        log_error "Interrupted CLI download left usable partial plaintext"
        return 1
    fi

    local upload_source="$TEST_ROOT/files/interrupted-upload.bin"
    local upload_log="$TEST_ROOT/interrupted-upload.log"
    "$CLIENT" generate-test-file --filename "$upload_source" --size 100000000 --pattern random >/dev/null || return 1
    "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        --verbose \
        upload \
        --file "$upload_source" \
        --password-type account >"$upload_log" 2>&1 &
    local upload_pid=$!
    local upload_started=false
    local attempt
    for ((attempt = 1; attempt <= 100; attempt++)); do
        if grep -q 'Uploading .* chunks' "$upload_log" 2>/dev/null; then
            upload_started=true
            break
        fi
        if ! kill -0 "$upload_pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if [ "$upload_started" != true ]; then
        wait "$upload_pid" 2>/dev/null || true
        log_error "Upload did not remain active long enough to exercise SIGINT handling"
        return 1
    fi
    kill -INT "$upload_pid"
    if ! wait "$upload_pid"; then
        log_error "Upload did not finish its active file cleanly after SIGINT"
        return 1
    fi
    if ! grep -q '^\[OK\].*file_id=' "$upload_log"; then
        log_error "Upload reported success without a completed file ID after SIGINT"
        return 1
    fi
    if find "$TEST_ROOT" -type f \( -name '*.part' -o -name '*.tmp' \) -print -quit | grep -q .; then
        log_error "Interrupted CLI operation left temporary files in its isolated HOME or output tree"
        return 1
    fi
    log_ok "CLI interruption cleanup checks passed"
}

run_live_download_limit_race() {
    if [ -z "$ACCOUNT_FILE_ID" ]; then
        log_error "Live race requires the account canary file"
        return 1
    fi

    local race_password="IntegrityRace-${RUN_ID}-Password!"
    printf 'race_share_password\t%s\n' "$race_password" >>"$CANARY_FILE"
    local output share_id
    if ! output="$(printf '%s\n' "$race_password" | "$CLIENT" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        share create \
        --password-stdin \
        --file-id "$ACCOUNT_FILE_ID" \
        --expires 0 \
        --max-downloads 1 2>&1)"; then
        log_error "Could not create one-download race share"
        return 1
    fi
    share_id="$(printf '%s\n' "$output" | awk '/Share ID:/ {print $3; exit}')"
    if [ -z "$share_id" ]; then
        log_error "Race share did not return a share ID"
        return 1
    fi

    (
        printf '%s\n' "$race_password" | "$CLIENT" --server-url "$SERVER_URL" --tls-insecure \
            share download --password-stdin --share-id "$share_id" --output "$TEST_ROOT/race-a.bin"
    ) >"$TEST_ROOT/race-a.log" 2>&1 &
    local first_pid=$!
    (
        printf '%s\n' "$race_password" | "$CLIENT" --server-url "$SERVER_URL" --tls-insecure \
            share download --password-stdin --share-id "$share_id" --output "$TEST_ROOT/race-b.bin"
    ) >"$TEST_ROOT/race-b.log" 2>&1 &
    local second_pid=$!

    local successes=0
    if wait "$first_pid"; then
        successes=$((successes + 1))
    fi
    if wait "$second_pid"; then
        successes=$((successes + 1))
    fi
    if [ "$successes" -ne 1 ]; then
        log_error "One-download share race produced $successes successes; expected exactly one"
        return 1
    fi
    log_ok "Live one-download authorization race allowed exactly one download"
}

record_group() {
    local name="$1"
    shift
    TESTS_RUN=$((TESTS_RUN + 1))
    printf '\n[RUN] %s\n' "$name"
    if "$@"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_ok "$name"
    else
        log_error "$name"
        return 1
    fi
}

capture_file_delta() {
    local baseline="$1"
    local post="$2"
    local output="$3"
    awk -F '\t' '
        NR == FNR {before[$1] = $2 FS $3; next}
        !($1 in before) || before[$1] != $2 FS $3 {print $1}
    ' "$baseline" "$post" >"$output"
}

capture_post_test_deltas() {
    capture_database "$TEST_ROOT/post/database.sql" || return 1
    HOME="$TEST_ROOT/home" "$ADMIN" \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        security-events --json --limit 500 >"$TEST_ROOT/delta/security-events.json" || return 1
    journalctl -u arkfile \
        --after-cursor "$(<"$TEST_ROOT/baseline/journal.cursor")" \
        --no-pager -o cat >"$TEST_ROOT/delta/journal.log" 2>/dev/null || return 1

    snapshot_arkfile_temp "$TEST_ROOT/post/tmp.tsv"
    snapshot_tree "$STORAGE_ROOT" "$TEST_ROOT/post/storage.tsv"
    snapshot_tree "$APP_LOG_ROOT" "$TEST_ROOT/post/logs.tsv"
    capture_file_delta "$TEST_ROOT/baseline/tmp.tsv" "$TEST_ROOT/post/tmp.tsv" "$TEST_ROOT/delta/tmp-files.txt"
    capture_file_delta "$TEST_ROOT/baseline/storage.tsv" "$TEST_ROOT/post/storage.tsv" "$TEST_ROOT/delta/storage-files.txt"
    capture_file_delta "$TEST_ROOT/baseline/logs.tsv" "$TEST_ROOT/post/logs.tsv" "$TEST_ROOT/delta/log-files.txt"
    comm -13 \
        <(sort "$TEST_ROOT/baseline/database.sql") \
        <(sort "$TEST_ROOT/post/database.sql") >"$TEST_ROOT/delta/database.sql"
}

scan_text_surface() {
    local surface="$1"
    local file="$2"
    local class value
    while IFS=$'\t' read -r class value; do
        [ -n "$value" ] || continue
        grep -aFq -- "$value" "$file"
        local status=$?
        if [ "$status" -eq 0 ]; then
            log_error "Privacy canary found on surface '$surface': class=$class"
            return 1
        fi
        if [ "$status" -gt 1 ]; then
            log_error "Could not scan privacy surface '$surface'"
            return 1
        fi
    done <"$CANARY_FILE"
}

scan_changed_files() {
    local surface="$1"
    local list="$2"
    local path class value
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in
            "$TEST_ROOT"/*|/tmp/arkfile-e2e-test-data/*) continue ;;
        esac
        test -f "$path" || continue
        while IFS=$'\t' read -r class value; do
            [ -n "$value" ] || continue
            grep -aFq -- "$value" "$path" 2>/dev/null
            local status=$?
            if [ "$status" -eq 0 ]; then
                log_error "Privacy canary found on surface '$surface': class=$class file=$path"
                return 1
            fi
            if [ "$status" -gt 1 ]; then
                log_error "Could not scan privacy surface '$surface': file=$path"
                return 1
            fi
        done <"$CANARY_FILE"
    done <"$list"
}

run_delta_inspection() {
    capture_post_test_deltas || return 1
    scan_text_surface service-journal "$TEST_ROOT/delta/journal.log" || return 1
    scan_text_surface security-events "$TEST_ROOT/delta/security-events.json" || return 1
    scan_text_surface application-database "$TEST_ROOT/delta/database.sql" || return 1
    scan_changed_files application-logs "$TEST_ROOT/delta/log-files.txt" || return 1
    scan_changed_files temporary-files "$TEST_ROOT/delta/tmp-files.txt" || return 1
    scan_changed_files stored-objects "$TEST_ROOT/delta/storage-files.txt" || return 1
    log_ok "No protected canary appeared in post-baseline server surfaces"
}

finalize_integrity_state() {
    stop_agent
    cleanup_user || return 1
    verify_preserved_e2e_state
}

main() {
    preflight || exit 1
    admin_login || exit 1
    capture_preserved_e2e_state || exit 1
    capture_baseline || exit 1

    record_group canary-flows run_canary_flows || exit 1
    if [ "$SKIP_RESOURCES" != true ]; then
        record_group streaming-memory run_resource_measurements || exit 1
        record_group interruption-cleanup run_interruption_checks || exit 1
    else
        log_info "Streaming memory and interruption groups skipped by explicit environment setting"
    fi
    if [ "$SKIP_RACES" != true ]; then
        record_group live-authorization-race run_live_download_limit_race || exit 1
    else
        log_info "Live race group skipped by explicit environment setting"
    fi
    record_group privacy-delta-inspection run_delta_inspection || exit 1
    record_group dedicated-state-cleanup finalize_integrity_state || exit 1

    printf '\n[STATS] Online integrity results\n'
    printf 'Groups run:    %d\n' "$TESTS_RUN"
    printf 'Groups passed: %d\n' "$TESTS_PASSED"
    printf 'Groups failed: %d\n' "$((TESTS_RUN - TESTS_PASSED))"
    log_ok "All selected online integrity groups passed"
}

main "$@"
