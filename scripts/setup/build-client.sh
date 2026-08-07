#!/bin/bash
# Standalone arkfile-client build and install (Group A glibc Linux amd64).
#
# Supported families: Debian/Ubuntu/Devuan 6, RHEL/Alma/Rocky/Fedora,
# openSUSE/SLES, and Arch (pacman). Builds only arkfile-client (no server,
# admin, TypeScript, or WASM).
# Build workspace: /tmp/arkfile-client-build (never /var/tmp/arkfile-build).
# Install path:    /opt/arkfile-cli/arkfile-client (never /opt/arkfile/bin).
#
# Usage (from repo root):
#   sudo bash scripts/setup/build-client.sh
#
# This path must not call dev-reset.sh. Deploy resets must not wipe
# /tmp/arkfile-client-build or /opt/arkfile-cli.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Locked client-only build root (exported before sourcing build-config).
export ARKFILE_BUILD_DIR="/tmp/arkfile-client-build"

# shellcheck source=build-config.sh
source "$SCRIPT_DIR/build-config.sh"

CLIENT_INSTALL_DIR="/opt/arkfile-cli"
CLIENT_INSTALL_BIN="${CLIENT_INSTALL_DIR}/arkfile-client"
CLIENT_BUILD_BIN="${BUILD_ROOT}/arkfile-client"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

die() {
    echo -e "${RED}[X] $*${NC}" >&2
    exit 1
}

info() {
    echo -e "${YELLOW}$*${NC}"
}

ok() {
    echo -e "${GREEN}[OK] $*${NC}"
}

require_group_a_host() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    if [ "$os" != "Linux" ]; then
        die "Group A standalone client builds require Linux (found ${os})."
    fi
    case "$arch" in
        x86_64|amd64) ;;
        *)
            die "Group A standalone client builds require amd64/x86_64 (found ${arch})."
            ;;
    esac
}

require_root_for_install() {
    if [ "$EUID" -ne 0 ]; then
        die "Install to ${CLIENT_INSTALL_BIN} requires root. Re-run with: sudo bash scripts/setup/build-client.sh"
    fi
}

check_go_version() {
    local required_version go_version
    required_version="$(grep '^go [0-9]' go.mod | awk '{print $2}')"
    if [ -z "$required_version" ]; then
        return 0
    fi
    if ! GO_BINARY="$(find_go_binary)"; then
        die "Go compiler not found. Install Go ${required_version}+ then retry."
    fi
    export GO_BINARY
    export GOTOOLCHAIN="${GOTOOLCHAIN:-go${required_version}+auto}"
    go_version="$("$GO_BINARY" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')" || true
    ok "Using Go binary: ${GO_BINARY} (reported ${go_version:-unknown}; need ${required_version}+)"
}

fix_vendor_ownership_safe() {
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" go.mod go.sum 2>/dev/null || true
        [ -d vendor ] && chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
        [ -d vendor_c ] && chown -R "$SUDO_USER:$SUDO_USER" vendor_c/ 2>/dev/null || true
        [ -f .vendor_cache ] && chown "$SUDO_USER:$SUDO_USER" .vendor_cache 2>/dev/null || true
        [ -d "$BUILD_ROOT" ] && chown -R "$SUDO_USER:$SUDO_USER" "$BUILD_ROOT/" 2>/dev/null || true
    fi
}

build_c_dependencies() {
    info "Ensuring C vendor sources (vendor_c/)..."
    if ! ./scripts/setup/ensure-vendor-c.sh; then
        die "Failed to provision C vendor sources"
    fi

    if ! c_libs_exist; then
        info "Building vendored OPAQUE/libsodium (in-tree under vendor_c/)..."
        fix_vendor_ownership_safe
        if ! ./scripts/setup/build-libopaque.sh; then
            echo "Missing build tools?" >&2
            print_client_build_deps_hint >&2
            die "Failed to build OPAQUE/libsodium static libraries"
        fi
        fix_vendor_ownership_safe
    else
        ok "Using existing in-tree OPAQUE/libsodium archives"
    fi

    if ! fido_cache_valid; then
        info "Building vendored FIDO stack under ${FIDO_PREFIX}..."
        fix_vendor_ownership_safe
        if ! ./scripts/setup/build-libfido2.sh; then
            echo "Missing build tools?" >&2
            print_client_build_deps_hint >&2
            die "Failed to build FIDO2 libraries"
        fi
        fix_vendor_ownership_safe
    else
        ok "Using existing FIDO cache for ${BUILD_PLATFORM}"
    fi
}

build_arkfile_client() {
    local cli_ldflags repro_flags

    if [ ! -f "$LIBSODIUM_A" ]; then
        die "Vendored libsodium archive not found: $LIBSODIUM_A"
    fi
    if ! fido_cache_valid; then
        die "FIDO libraries missing under ${FIDO_PREFIX}"
    fi

    ensure_build_dir
    cli_ldflags="$(cli_go_ldflags)"
    repro_flags='-trimpath -buildvcs=false'

    export CGO_ENABLED=1
    export CGO_CFLAGS="$(cli_fido_cgo_cflags)"
    # shellcheck disable=SC2086
    export CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$REPO_ROOT")"

    if [ -z "${GO_BINARY:-}" ]; then
        if ! GO_BINARY="$(find_go_binary)"; then
            die "Go compiler not found"
        fi
        export GO_BINARY
    fi

    info "Building arkfile-client (version $(resolve_build_version), commit $(resolve_git_commit))..."
    info "BUILD_ROOT=${BUILD_ROOT}"
    info "CGO_CFLAGS=${CGO_CFLAGS}"

    # Match build.sh: invoke go in this shell so CGO_* exports survive sudo.
    # run_go_as_user strips CGO_CFLAGS/LDFLAGS via sudo -u env reset.
    # shellcheck disable=SC2086
    if ! "$GO_BINARY" build -a -mod=vendor $repro_flags -ldflags "$cli_ldflags" -o "$CLIENT_BUILD_BIN" ./cmd/arkfile-client; then
        die "go build ./cmd/arkfile-client failed"
    fi

    export CGO_ENABLED=0
    unset CGO_CFLAGS CGO_LDFLAGS

    fix_vendor_ownership_safe

    if [ ! -x "$CLIENT_BUILD_BIN" ]; then
        die "Built binary missing or not executable: $CLIENT_BUILD_BIN"
    fi
    ok "Built ${CLIENT_BUILD_BIN}"
}

verify_and_install() {
    info "Verifying CLI link policy..."
    if ! verify_cli_binary_linking "$CLIENT_BUILD_BIN"; then
        ldd "$CLIENT_BUILD_BIN" 2>&1 || true
        die "Link verification failed for ${CLIENT_BUILD_BIN}"
    fi

    info "Installing to ${CLIENT_INSTALL_BIN}..."
    mkdir -p "$CLIENT_INSTALL_DIR"
    install -m 0755 "$CLIENT_BUILD_BIN" "$CLIENT_INSTALL_BIN"

    # Keep install tree distinct from /opt/arkfile; readable/executable by others is fine.
    chmod 755 "$CLIENT_INSTALL_DIR"
    chmod 755 "$CLIENT_INSTALL_BIN"

    ok "Installed ${CLIENT_INSTALL_BIN}"
    if "$CLIENT_INSTALL_BIN" -V >/dev/null 2>&1; then
        ok "Version: $("$CLIENT_INSTALL_BIN" -V)"
    else
        die "Installed binary failed: ${CLIENT_INSTALL_BIN} -V"
    fi
}

main() {
    require_group_a_host
    require_root_for_install

    if [ ! -f go.mod ] || [ ! -d cmd/arkfile-client ]; then
        die "Run from the Arkfile repository root (go.mod / cmd/arkfile-client missing)"
    fi

    detect_build_platform
    init_fido_paths

    echo "Arkfile standalone arkfile-client build"
    echo "  Host family: $(detect_package_os_family)"
    echo "  Platform:    ${BUILD_PLATFORM}"
    echo "  Build root:  ${BUILD_ROOT}"
    echo "  Install to:  ${CLIENT_INSTALL_BIN}"
    print_client_build_deps_hint

    check_go_version
    fix_vendor_ownership_safe

    if ! verify_go_mod_vendor_consistency; then
        die "go.mod / vendor/ inconsistent; fix before building the client"
    fi

    build_c_dependencies
    build_arkfile_client
    verify_and_install

    echo ""
    ok "Standalone arkfile-client ready"
    echo "  Prove with deploy client:  bash scripts/testing/e2e-test.sh"
    echo "  Prove with this binary:    bash scripts/testing/e2e-test.sh --client-path ${CLIENT_INSTALL_BIN}"
    echo "  Note: dev-reset must not remove ${CLIENT_INSTALL_DIR} or ${BUILD_ROOT}"
}

main "$@"
