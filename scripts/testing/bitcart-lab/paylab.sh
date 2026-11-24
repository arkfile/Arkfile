#!/bin/bash
# Rootless-only launcher and helper for the Bitcart payment lab.
# Refuses root/sudo, strips any Docker daemon environment variables, verifies
# Podman is running in rootless mode, and pins compose to the current user's
# rootless Podman socket even when Docker and docker-compose-plugin are also
# installed on the host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../testing-common.sh
source "$SCRIPT_DIR/../testing-common.sh"

testing_refuse_root "bitcart-lab/paylab.sh"

if [ -n "${SUDO_USER:-}" ]; then
    echo "[X] bitcart-lab/paylab.sh must be invoked directly as your regular user, without sudo." >&2
    exit 1
fi

LAB_TMP_DIR="/tmp/arkfile-bitcart-lab"
LAB_HOME_DIR="${LAB_TMP_DIR}/home"
LAB_CA_PATH="${LAB_TMP_DIR}/ca.crt"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"
ENV_FILE="${SCRIPT_DIR}/lab.env"

testing_require_owned_dir "$LAB_TMP_DIR" "bitcart-lab/paylab.sh"

# Strip any caller environment variables that could point a compose plugin at
# a rootful Docker or rootful Podman daemon.
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
unset CONTAINER_HOST CONTAINER_CONNECTION

if ! command -v podman >/dev/null 2>&1; then
    echo "[X] podman is not installed." >&2
    exit 1
fi

rootless_state="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
if [ "$rootless_state" != "true" ]; then
    echo "[X] Podman did not report rootless mode (Rootless=${rootless_state:-unknown})." >&2
    echo "    Refusing to run containers in rootful mode." >&2
    exit 1
fi

caller_uid="$(id -u)"
runtime_dir="${XDG_RUNTIME_DIR:-/run/user/${caller_uid}}"
podman_sock="${runtime_dir}/podman/podman.sock"

if [ ! -S "$podman_sock" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user start podman.socket 2>/dev/null || true
fi

if [ -S "$podman_sock" ]; then
    sock_uid="$(stat -c '%u' "$podman_sock" 2>/dev/null || echo "")"
    if [ "$sock_uid" != "$caller_uid" ] || [ "$sock_uid" = "0" ]; then
        echo "[X] Rootless Podman socket ${podman_sock} is owned by uid '${sock_uid}', expected '${caller_uid}'." >&2
        exit 1
    fi
    export CONTAINER_HOST="unix://${podman_sock}"
    export DOCKER_HOST="unix://${podman_sock}"
    export PODMAN_COMPOSE_WARNING_LOGS=false
elif command -v podman-compose >/dev/null 2>&1; then
    export PODMAN_COMPOSE_PROVIDER=podman-compose
    export PODMAN_COMPOSE_WARNING_LOGS=false
else
    echo "[X] Rootless Podman socket not found at ${podman_sock} and podman-compose is not installed." >&2
    echo "    Enable the user socket with: systemctl --user enable --now podman.socket" >&2
    exit 1
fi

run_compose() {
    local args=(-f "$COMPOSE_FILE")
    if [ -f "$ENV_FILE" ]; then
        args+=(--env-file "$ENV_FILE")
    fi
    podman compose "${args[@]}" "$@"
}

# Copy the already-built host install into a small build context. The image
# does not compile Arkfile. Only the fully static server binary goes into the
# image; arkfile-admin and arkfile-client run natively on the host.
stage_arkfile_image() {
    local src="/opt/arkfile"
    local stage="${LAB_TMP_DIR}/image"
    local need
    for need in \
        "$src/bin/arkfile" \
        "$src/client/static/index.html" \
        "$src/client/static/js/libopaque.js" \
        "$src/client/static/js/dist/app.js" \
        "$src/database/unified_schema.sql"
    do
        if [ ! -e "$need" ]; then
            echo "[X] Missing ${need}." >&2
            echo "    Build the host install with dev-reset.sh or local-deploy.sh before starting the lab." >&2
            exit 1
        fi
    done
    rm -rf "$stage"
    mkdir -p "$stage/client" "$stage/database"
    cp -a "$src/bin/arkfile" "$stage/"
    cp -a "$src/client/." "$stage/client/"
    cp -a "$src/database/." "$stage/database/"
    cp -a "$SCRIPT_DIR/entrypoint-arkfile.sh" "$SCRIPT_DIR/Containerfile.arkfile" "$stage/"
    export ARKFILE_PAYLAB_IMAGE_CONTEXT="$stage"
}

ensure_lab_ca() {
    mkdir -p -m 700 "$LAB_TMP_DIR" "$LAB_HOME_DIR"
    if [ "${1:-}" = "force" ] || [ ! -s "$LAB_CA_PATH" ]; then
        run_compose cp arkfile:/ca/ca.crt "$LAB_CA_PATH"
        chmod 0644 "$LAB_CA_PATH"
    fi
}

require_arkfile_cid() {
    local cid
    cid="$(run_compose ps -q arkfile 2>/dev/null | head -n 1 || true)"
    if [ -z "$cid" ]; then
        echo "[X] arkfile container is not running. Start the lab first with: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
        exit 1
    fi
    if ! env -u CONTAINER_HOST -u DOCKER_HOST podman exec "$cid" sh -c 'command -v socat >/dev/null 2>&1'; then
        echo "[X] Running arkfile container is missing socat. Recreate it with: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
        exit 1
    fi
    printf '%s\n' "$cid"
}

# Run the host's native arkfile-admin binary over an ephemeral 127.0.0.1 TCP
# tunnel into the arkfile container's loopback interface so DirectLocalMiddleware
# sees 127.0.0.1 and host glibc/libudev differences across distros never matter.
run_host_admin() {
    local admin_bin="${ARKFILE_ADMIN_BIN:-/opt/arkfile/bin/arkfile-admin}"
    if [ ! -x "$admin_bin" ]; then
        echo "[X] arkfile-admin binary not found at ${admin_bin} (override with ARKFILE_ADMIN_BIN)." >&2
        exit 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[X] python3 is required on the host to tunnel arkfile-admin into the container." >&2
        exit 1
    fi
    ensure_lab_ca
    local arkfile_cid
    arkfile_cid="$(require_arkfile_cid)"

    (
        port_file="$(mktemp "${LAB_TMP_DIR}/admin-tunnel.XXXXXX")"
        tunnel_pid=""
        cleanup_tunnel() {
            if [ -n "$tunnel_pid" ]; then
                kill "$tunnel_pid" 2>/dev/null || true
                wait "$tunnel_pid" 2>/dev/null || true
            fi
            rm -f "$port_file"
        }
        trap cleanup_tunnel EXIT INT TERM

        env -u CONTAINER_HOST -u DOCKER_HOST python3 -c '
import asyncio, os, sys

cid, port_file = sys.argv[1], sys.argv[2]

async def pipe_to_stdin(reader, proc):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            proc.stdin.write(chunk)
            await proc.stdin.drain()
    except Exception:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass

async def pipe_from_stdout(proc, writer):
    try:
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_client(reader, writer):
    proc = await asyncio.create_subprocess_exec(
        "podman", "exec", "-i", cid, "socat", "STDIO", "TCP4:127.0.0.1:18443",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await asyncio.gather(pipe_to_stdin(reader, proc), pipe_from_stdout(proc, writer))
    try:
        await proc.wait()
    except Exception:
        pass

async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    tmp = port_file + ".ready"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"{port}\n")
    os.replace(tmp, port_file)
    async with server:
        await server.serve_forever()

asyncio.run(main())
' "$arkfile_cid" "$port_file" </dev/null >/dev/null 2>&1 &
        tunnel_pid="$!"

        tunnel_port=""
        for _ in $(seq 1 100); do
            if [ -s "$port_file" ]; then
                tunnel_port="$(cat "$port_file")"
                break
            fi
            if ! kill -0 "$tunnel_pid" 2>/dev/null; then
                break
            fi
            sleep 0.02
        done
        if [ -z "$tunnel_port" ]; then
            echo "[X] Failed to open loopback tunnel to arkfile container." >&2
            exit 1
        fi

        HOME="$LAB_HOME_DIR" SSL_CERT_FILE="$LAB_CA_PATH" \
            "$admin_bin" --server-url "https://127.0.0.1:${tunnel_port}" "$@"
    )
}

require_lab_env() {
    if [ ! -f "$ENV_FILE" ]; then
        echo "[X] Missing ${ENV_FILE}." >&2
        echo "    Copy ${SCRIPT_DIR}/lab.env.example to ${ENV_FILE}, chmod 600, and fill in BTC_XPUB and BITCART_ADMIN_PASSWORD." >&2
        exit 1
    fi
    chmod 600 "$ENV_FILE"
}

usage() {
    cat <<'EOF'
Usage: bash scripts/testing/bitcart-lab/paylab.sh <command> [args...]

Commands:
  up [args...]               Build and start the lab in rootless Podman (auto-enables --profile xmr when BITCART_CRYPTOS includes xmr)
  stop                       Stop lab containers without removing volumes
  down                       Stop lab containers and delete all lab volumes (clean slate)
  ps                         Show lab container status
  logs [args...]             View lab logs (for example: logs -f provision arkfile worker)
  export-ca                  Copy the lab CA certificate to /tmp/arkfile-bitcart-lab/ca.crt
  verify [--check-invoice]   Verify strict public gateway routes, security headers, store settings, and Electrum auto_connect=false
  bootstrap-admin [username] Bootstrap the lab admin via host arkfile-admin over loopback tunnel (default: paylab-admin)
  admin <args...>            Run host arkfile-admin against the lab over an ephemeral loopback tunnel
  client <args...>           Run host arkfile-client against https://arkfile.lab:18443 with isolated HOME and SSL_CERT_FILE
  compose <args...>          Run an arbitrary podman compose command under rootless enforcement
EOF
}

run_verify() {
    local check_invoice=false
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --check-invoice) check_invoice=true ;;
            -h|--help)
                cat <<'EOF'
Usage: bash scripts/testing/bitcart-lab/paylab.sh verify [--check-invoice]
  --check-invoice  Create one live test invoice to verify per-coin confirmation floors and /i/<id> checkout rendering
EOF
                return 0
                ;;
            *)
                echo "[X] Unknown verify option: $1" >&2
                return 1
                ;;
        esac
        shift
    done

    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        echo "[X] curl and jq are required on the host to run paylab.sh verify." >&2
        return 1
    fi

    ensure_lab_ca
    local arkfile_cid bitcoin_cid
    arkfile_cid="$(require_arkfile_cid)"
    bitcoin_cid="$(run_compose ps -q bitcoin 2>/dev/null | head -n 1 || true)"

    local bitcart_env store_id api_token
    bitcart_env="$(env -u CONTAINER_HOST -u DOCKER_HOST podman exec "$arkfile_cid" cat /lab-config/bitcart.env 2>/dev/null || true)"
    store_id="$(printf '%s\n' "$bitcart_env" | awk -F= '$1 == "ARKFILE_BITCART_STORE_ID" { print substr($0, index($0, "=") + 1); exit }')"
    api_token="$(printf '%s\n' "$bitcart_env" | awk -F= '$1 == "ARKFILE_BITCART_API_TOKEN" { print substr($0, index($0, "=") + 1); exit }')"
    if [ -z "$store_id" ] || [ -z "$api_token" ]; then
        echo "[X] Could not read ARKFILE_BITCART_STORE_ID / ARKFILE_BITCART_API_TOKEN from arkfile:/lab-config/bitcart.env." >&2
        return 1
    fi

    local want_xmr=0
    if [ -f "$ENV_FILE" ] && grep -Eq '^[[:space:]]*BITCART_CRYPTOS=.*xmr' "$ENV_FILE"; then
        want_xmr=1
    fi

    local failures=0
    local http_status="" http_body="" http_headers=""

    verify_pass() { echo "[OK] $*"; }
    verify_fail() { echo "[X] $*" >&2; failures=$((failures + 1)); }

    lab_public_request() {
        local method="$1"
        local path="$2"
        local token="${3:-}"
        local body="${4:-}"
        local tmp_body tmp_hdr tmp_cfg
        tmp_body="$(mktemp "${LAB_TMP_DIR}/verify-body.XXXXXX")"
        tmp_hdr="$(mktemp "${LAB_TMP_DIR}/verify-hdr.XXXXXX")"
        tmp_cfg="$(mktemp "${LAB_TMP_DIR}/verify-cfg.XXXXXX")"
        chmod 0600 "$tmp_body" "$tmp_hdr" "$tmp_cfg"

        {
            printf 'silent\n'
            printf 'show-error\n'
            printf 'max-time = 20\n'
            printf 'cacert = "%s"\n' "$LAB_CA_PATH"
            printf 'resolve = "bitcart.lab:19080:127.0.0.1"\n'
            printf 'request = "%s"\n' "$method"
            printf 'url = "https://bitcart.lab:19080%s"\n' "$path"
            printf 'dump-header = "%s"\n' "$tmp_hdr"
            if [ -n "$token" ]; then
                printf 'header = "Authorization: Bearer %s"\n' "$token"
            fi
            if [ -n "$body" ]; then
                printf 'header = "Content-Type: application/json"\n'
            fi
        } > "$tmp_cfg"

        if [ -n "$body" ]; then
            http_status="$(printf '%s' "$body" | curl -K "$tmp_cfg" --data-binary @- -o "$tmp_body" -w '%{http_code}' || printf '000')"
        else
            http_status="$(curl -K "$tmp_cfg" -o "$tmp_body" -w '%{http_code}' || printf '000')"
        fi
        http_body="$(cat "$tmp_body")"
        http_headers="$(cat "$tmp_hdr")"
        rm -f "$tmp_body" "$tmp_hdr" "$tmp_cfg"
    }

    check_blocked() {
        local method="$1" path="$2" token="$3" body="$4" label="$5"
        lab_public_request "$method" "$path" "$token" "$body"
        if [ "$http_status" = "404" ]; then
            verify_pass "Blocked public route returns 404: ${label}"
        else
            verify_fail "Blocked public route ${label} returned HTTP ${http_status} (expected 404)."
        fi
    }

    # 1. Token auth checks on /api/invoices/count
    lab_public_request "GET" "/api/invoices/count" "$api_token"
    if [ "$http_status" = "200" ]; then
        verify_pass "GET /api/invoices/count with merchant token returned 200."
    else
        verify_fail "GET /api/invoices/count with merchant token returned HTTP ${http_status} (expected 200)."
    fi

    lab_public_request "GET" "/api/invoices/count"
    if [ "$http_status" = "401" ]; then
        verify_pass "Unauthenticated GET /api/invoices/count returned 401."
    else
        verify_fail "Unauthenticated GET /api/invoices/count returned HTTP ${http_status} (expected 401)."
    fi

    # 2. Store checkout settings (PublicStore) and enabled cryptos
    lab_public_request "GET" "/api/stores/${store_id}" "$api_token"
    if [ "$http_status" = "200" ] && jq -e '
        (.default_currency | ascii_upcase) == "USD" and
        (.checkout_settings.expiration == 60) and
        (.checkout_settings.transaction_speed >= 1) and
        (.checkout_settings.underpaid_percentage == 0) and
        (.checkout_settings.email_required == false) and
        (.checkout_settings.allow_anonymous_invoice_creation == false)
    ' >/dev/null <<< "$http_body"; then
        verify_pass "Store ${store_id} USD and checkout_settings verified."
    else
        verify_fail "Store ${store_id} check failed (HTTP ${http_status})."
    fi

    lab_public_request "GET" "/api/cryptos"
    if [ "$http_status" = "200" ] && jq -e --argjson want_xmr "$want_xmr" '
        (if type == "array" then . elif (type == "object" and (.result | type == "array")) then .result else [] end)
        | [.[] | ascii_downcase]
        | (index("btc") != null) and ($want_xmr == 0 or index("xmr") != null)
    ' >/dev/null <<< "$http_body"; then
        verify_pass "GET /api/cryptos reports enabled coin daemon(s)."
    else
        verify_fail "GET /api/cryptos check failed (HTTP ${http_status}): ${http_body}"
    fi

    # 3. Anonymous invoice creation blocked
    local anon_payload
    anon_payload="$(jq -n --arg sid "$store_id" '{price: 1, currency: "USD", store_id: $sid}')"
    lab_public_request "POST" "/api/invoices" "" "$anon_payload"
    if [ "$http_status" = "403" ]; then
        verify_pass "Unauthenticated POST /api/invoices returned 403."
    else
        verify_fail "Unauthenticated POST /api/invoices returned HTTP ${http_status} (expected 403)."
    fi

    # 4. Strict public gateway route blocks on :19080
    local batch_payload
    batch_payload='{"ids":["00000000000000000000000000"],"command":"mark_complete"}'
    check_blocked "GET" "/" "" "" "GET /"
    check_blocked "POST" "/api/token" "" '{"email":"x@y.z","password":"z"}' "POST /api/token"
    check_blocked "POST" "/api/invoices/batch" "$api_token" "$batch_payload" "POST /api/invoices/batch (with valid merchant token)"
    check_blocked "GET" "/api/invoices/export" "$api_token" "" "GET /api/invoices/export"
    check_blocked "PATCH" "/api/invoices/00000000000000000000000000/customer" "" '{"buyer_email":"a@b.c"}' "PATCH /api/invoices/{id}/customer"
    check_blocked "GET" "/api/wallets" "$api_token" "" "GET /api/wallets"

    # 5. Security headers on :19080
    lab_public_request "GET" "/api/manage/policies"
    if [ "$http_status" = "200" ]; then
        verify_pass "GET /api/manage/policies returned 200."
    else
        verify_fail "GET /api/manage/policies returned HTTP ${http_status} (expected 200)."
    fi
    for hdr in "strict-transport-security:" "referrer-policy:[[:space:]]*no-referrer" "x-content-type-options:[[:space:]]*nosniff" "x-frame-options:[[:space:]]*DENY"; do
        if grep -iq "^${hdr}" <<< "$http_headers"; then
            verify_pass "Public gateway header present: ${hdr}"
        else
            verify_fail "Public gateway header missing: ${hdr}"
        fi
    done

    # 6. Electrum auto_connect=false check inside bitcoin container
    if [ -n "$bitcoin_cid" ]; then
        local btc_cfg
        btc_cfg="$(env -u CONTAINER_HOST -u DOCKER_HOST podman exec "$bitcoin_cid" cat /data/config 2>/dev/null || true)"
        if jq -e '.auto_connect == false' >/dev/null 2>&1 <<< "$btc_cfg"; then
            verify_pass "Electrum /data/config has auto_connect=false."
        else
            verify_fail "Electrum /data/config missing auto_connect=false."
        fi
    else
        verify_fail "bitcoin container is not running."
    fi

    # 7. Optional live invoice verification (--check-invoice)
    if [ "$check_invoice" = "true" ]; then
        local inv_payload inv_id
        inv_payload="$(jq -n --arg sid "$store_id" --arg oid "paylab-verify-$(date +%s)" '{price: 1, currency: "USD", store_id: $sid, order_id: $oid}')"
        lab_public_request "POST" "/api/invoices" "$api_token" "$inv_payload"
        inv_id="$(jq -r '.id // empty' <<< "$http_body" 2>/dev/null || true)"
        if [ "$http_status" = "200" ] && [ -n "$inv_id" ]; then
            verify_pass "Live invoice created via :19080 (${inv_id})."
            if jq -e '[.payments[] | select((.currency // "" | ascii_downcase) == "btc") | (.required_confirmations // 0)] | length > 0 and all(. >= 1)' >/dev/null <<< "$http_body"; then
                verify_pass "BTC payment method requires >= 1 confirmation."
            else
                verify_fail "BTC payment method missing or required_confirmations < 1."
            fi
            if [ "$want_xmr" -eq 1 ]; then
                if jq -e '[.payments[] | select((.currency // "" | ascii_downcase) == "xmr") | (.required_confirmations // 0)] | length > 0 and all(. >= 5)' >/dev/null <<< "$http_body"; then
                    verify_pass "XMR payment method requires >= 5 confirmations."
                else
                    verify_fail "XMR payment method missing or required_confirmations < 5."
                fi
            fi
            lab_public_request "GET" "/i/${inv_id}"
            if [ "$http_status" = "200" ]; then
                verify_pass "Checkout page GET /i/${inv_id} returned 200."
            else
                verify_fail "Checkout page GET /i/${inv_id} returned HTTP ${http_status} (expected 200)."
            fi
        else
            verify_fail "Live invoice creation failed (HTTP ${http_status})."
        fi
    fi

    if [ "$failures" -gt 0 ]; then
        echo "[X] Lab verification failed with ${failures} error(s)." >&2
        return 1
    fi
    echo "[OK] All Bitcart lab parity and security checks passed."
}

cmd="${1:-help}"
shift || true

case "$cmd" in
    up)
        require_lab_env
        stage_arkfile_image
        profile_args=()
        if grep -Eq '^[[:space:]]*BITCART_CRYPTOS=.*xmr' "$ENV_FILE"; then
            profile_args+=(--profile xmr)
        fi
        run_compose "${profile_args[@]}" up -d --build "$@"
        ;;
    stop)
        run_compose --profile xmr stop "$@"
        ;;
    down)
        run_compose --profile xmr down -v "$@"
        ;;
    ps)
        run_compose ps "$@"
        ;;
    logs)
        run_compose logs "$@"
        ;;
    export-ca)
        ensure_lab_ca force
        echo "[OK] Lab CA written to ${LAB_CA_PATH}"
        ;;
    verify)
        run_verify "$@"
        ;;
    bootstrap-admin)
        admin_user="${1:-paylab-admin}"
        arkfile_cid="$(require_arkfile_cid)"
        bootstrap_token="$(env -u CONTAINER_HOST -u DOCKER_HOST podman exec "$arkfile_cid" cat /opt/arkfile/etc/keys/bootstrap-token.bin 2>/dev/null || true)"
        if [ -z "$bootstrap_token" ]; then
            echo "[X] No bootstrap token found at /opt/arkfile/etc/keys/bootstrap-token.bin inside arkfile." >&2
            echo "    If an admin was already bootstrapped, sign in with: bash scripts/testing/bitcart-lab/paylab.sh admin --username ${admin_user} login" >&2
            exit 1
        fi
        printf '%s\n' "$bootstrap_token" | run_host_admin bootstrap --token-stdin --username "$admin_user"
        ;;
    admin)
        if [ "$#" -eq 0 ]; then
            echo "[X] Provide an arkfile-admin subcommand (for example: payments check)." >&2
            exit 1
        fi
        run_host_admin "$@"
        ;;
    client)
        if [ "$#" -eq 0 ]; then
            echo "[X] Provide an arkfile-client subcommand." >&2
            exit 1
        fi
        ensure_lab_ca
        client_bin="${ARKFILE_CLIENT_BIN:-/opt/arkfile/bin/arkfile-client}"
        if [ ! -x "$client_bin" ]; then
            echo "[X] arkfile-client binary not found at ${client_bin} (override with ARKFILE_CLIENT_BIN)." >&2
            exit 1
        fi
        HOME="$LAB_HOME_DIR" SSL_CERT_FILE="$LAB_CA_PATH" \
            "$client_bin" --server-url https://arkfile.lab:18443 "$@"
        ;;
    compose)
        run_compose "$@"
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        echo "[X] Unknown command: ${cmd}" >&2
        usage >&2
        exit 1
        ;;
esac
