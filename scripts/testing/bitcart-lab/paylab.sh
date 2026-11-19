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
  bootstrap-admin [username] Bootstrap the lab admin via host arkfile-admin over loopback tunnel (default: paylab-admin)
  admin <args...>            Run host arkfile-admin against the lab over an ephemeral loopback tunnel
  client <args...>           Run host arkfile-client against https://arkfile.lab:18443 with isolated HOME and SSL_CERT_FILE
  compose <args...>          Run an arbitrary podman compose command under rootless enforcement
EOF
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
