#!/bin/bash
# Shared build configuration for Arkfile
# Source this file in all build/setup/deploy scripts
#
# Usage: source "$(dirname "$0")/build-config.sh" 2>/dev/null || source scripts/setup/build-config.sh

# =============================================================================
# BUILD ROOT CONFIGURATION
# =============================================================================
# Default to /var/tmp/arkfile-build for POSIX compliance across all target OSs
# Override with ARKFILE_BUILD_DIR environment variable if needed
export BUILD_ROOT="${ARKFILE_BUILD_DIR:-/var/tmp/arkfile-build}"

# =============================================================================
# BUILD SUBDIRECTORIES
# =============================================================================
export BUILD_BIN="$BUILD_ROOT/bin"                    # Go binaries
export BUILD_CLIENT="$BUILD_ROOT/client"              # Client static files
export BUILD_CLIENT_JS="$BUILD_ROOT/client/static/js" # JavaScript/TypeScript
export BUILD_CLIENT_JS_DIST="$BUILD_ROOT/client/static/js/dist"  # TS compiled output
export BUILD_CLIBS="$BUILD_ROOT/c-libs"               # C static libraries (.a files)
export BUILD_WASM="$BUILD_ROOT/wasm"                  # WASM build output
export BUILD_EMSDK="$BUILD_ROOT/emsdk"                # Emscripten SDK
export BUILD_DATABASE="$BUILD_ROOT/database"          # Database schema copies
export BUILD_SYSTEMD="$BUILD_ROOT/systemd"            # Systemd service copies
export BUILD_WEBROOT="$BUILD_ROOT/webroot"            # Web root (error pages, etc.)

# =============================================================================
# SOURCE DIRECTORIES (in repo)
# =============================================================================
export SRC_CLIENT="client/static"
export SRC_CLIENT_JS="client/static/js"
export SRC_CLIENT_JS_SRC="client/static/js/src"
export SRC_DATABASE="database"
export SRC_SYSTEMD="systemd"
export SRC_VENDOR_STEF="vendor_c/stef"

# =============================================================================
# C VENDOR PATHS (vendor_c/ -- never modified by go mod vendor)
# =============================================================================
export VENDOR_C_ROOT="vendor_c"
export VENDOR_C_STEF="$VENDOR_C_ROOT/stef"
export VENDOR_C_LIBOPAQUE_DIR="$VENDOR_C_STEF/libopaque"
export VENDOR_C_LIBOPRF_DIR="$VENDOR_C_STEF/liboprf"
export LIBOPAQUE_SRC="$VENDOR_C_LIBOPAQUE_DIR/src"
export LIBOPRF_SRC="$VENDOR_C_LIBOPRF_DIR/src"
export OPAQUE_C_SOURCE="$LIBOPAQUE_SRC/opaque.c"
export OPRF_C_SOURCE="$LIBOPRF_SRC/oprf.c"

export VENDOR_C_LIBOPAQUE_COMMIT="${VENDOR_C_LIBOPAQUE_COMMIT:-6e9ac92f9a2289679e04b0b0c5fdc307bb3de54e}"
export VENDOR_C_LIBOPRF_COMMIT="${VENDOR_C_LIBOPRF_COMMIT:-a8c0410c1cfab9e8dddc8c5f6197d4f7226f6228}"
export VENDOR_C_LIBSODIUM_TAG="${VENDOR_C_LIBSODIUM_TAG:-1.0.20}"

# =============================================================================
# C LIBRARY PATHS
# =============================================================================
export LIBOPAQUE_A="$LIBOPAQUE_SRC/libopaque.a"
export LIBOPRF_A="$LIBOPRF_SRC/liboprf.a"
export NOISE_XK_A="$LIBOPRF_SRC/noise_xk/liboprf-noiseXK.a"

# Native libsodium is vendored and built from source.
export LIBSODIUM_DIR="$VENDOR_C_ROOT/jedisct1/libsodium"
export LIBSODIUM_INCLUDE="$LIBSODIUM_DIR/src/libsodium/include"
export LIBSODIUM_A="$LIBSODIUM_DIR/src/libsodium/.libs/libsodium.a"

# CLI FIDO2 stack (libfido2 + libcbor + zlib + libcrypto); not linked by the server.
# Paths are set by init_fido_paths() after detect_build_platform() (per BUILD_PLATFORM).
export FIDO_PREFIX=""
export FIDO_LIB=""
export FIDO_BUILD_STAMP_FILE=""

init_fido_paths() {
    detect_build_platform
    export FIDO_PREFIX="${BUILD_CLIBS}/fido/${BUILD_PLATFORM}"
    export FIDO_LIB="${FIDO_PREFIX}/lib/libfido2.a"
    export FIDO_BUILD_STAMP_FILE="${FIDO_PREFIX}/.build-platform-stamp"
}

# =============================================================================
# CROSS-PLATFORM BUILD DETECTION (shared by libopaque, libfido2, build.sh)
# =============================================================================

find_make_command() {
    if command -v gmake >/dev/null 2>&1; then
        echo "gmake"
    elif command -v make >/dev/null 2>&1; then
        echo "make"
    else
        return 1
    fi
}

get_parallel_jobs() {
    local n=2

    if command -v getconf >/dev/null 2>&1; then
        n="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
    elif command -v nproc >/dev/null 2>&1; then
        n="$(nproc 2>/dev/null || true)"
    elif command -v sysctl >/dev/null 2>&1; then
        n="$(sysctl -n hw.ncpu 2>/dev/null || true)"
    fi

    if [ -z "$n" ] || ! [ "$n" -gt 0 ] 2>/dev/null; then
        n=2
    fi

    # Heavy vendored C builds: use half of online CPUs (minimum 1).
    if [ "$n" -gt 1 ] 2>/dev/null; then
        n=$(( n / 2 ))
    fi

    echo "$n"
}

# Normalise uname -s / -m into BUILD_OS, BUILD_ARCH, BUILD_PLATFORM.
detect_build_platform() {
    local raw_os raw_arch
    raw_os="$(uname -s)"
    raw_arch="$(uname -m)"

    case "$raw_os" in
        Linux)     BUILD_OS=linux ;;
        FreeBSD)   BUILD_OS=freebsd ;;
        OpenBSD)   BUILD_OS=openbsd ;;
        Darwin)    BUILD_OS=darwin ;;
        *)         BUILD_OS=unknown ;;
    esac

    case "$raw_arch" in
        x86_64|amd64)          BUILD_ARCH=amd64 ;;
        aarch64|arm64)         BUILD_ARCH=arm64 ;;
        armv7l|armv6l|armv7)   BUILD_ARCH=arm32 ;;
        i386|i686)             BUILD_ARCH=x86 ;;
        ppc64le)               BUILD_ARCH=ppc64le ;;
        ppc64|powerpc64)       BUILD_ARCH=ppc64 ;;
        riscv64)               BUILD_ARCH=riscv64 ;;
        s390x)                 BUILD_ARCH=s390x ;;
        *)                     BUILD_ARCH="$raw_arch" ;;
    esac

    export BUILD_OS BUILD_ARCH BUILD_PLATFORM="${BUILD_OS}-${BUILD_ARCH}"
}

# Map host triplet to an OpenSSL 3 ./Configure target for vendored libcrypto.
detect_openssl_configure_target() {
    detect_build_platform
    local target=""

    case "$BUILD_OS" in
        linux)
            case "$BUILD_ARCH" in
                amd64)    target="linux-x86_64" ;;
                arm64)    target="linux-aarch64" ;;
                arm32)    target="linux-armv4" ;;
                x86)      target="linux-x86" ;;
                ppc64le)  target="linux-ppc64le" ;;
                ppc64)    target="linux-ppc64" ;;
                riscv64)  target="linux-riscv64" ;;
                s390x)    target="linux-s390x" ;;
            esac
            ;;
        freebsd)
            case "$BUILD_ARCH" in
                amd64)  target="BSD-x86_64" ;;
                arm64)  target="BSD-aarch64" ;;
                x86)    target="BSD-x86" ;;
            esac
            ;;
        openbsd)
            case "$BUILD_ARCH" in
                amd64)  target="openbsd-amd64" ;;
                arm64)  target="openbsd-arm64" ;;
            esac
            ;;
        darwin)
            case "$BUILD_ARCH" in
                amd64)  target="darwin64-x86_64-cc" ;;
                arm64)  target="darwin64-arm64-cc" ;;
            esac
            ;;
    esac

    if [ -z "$target" ]; then
        echo "[X] No OpenSSL Configure target for ${BUILD_OS}/${BUILD_ARCH} ($(uname -s)/$(uname -m))" >&2
        return 1
    fi
    echo "$target"
}

is_linux_musl() {
    detect_build_platform
    [ "$BUILD_OS" = "linux" ] || return 1
    if [ -f /etc/alpine-release ]; then
        return 0
    fi
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
        return 0
    fi
    return 1
}

# OS-provided libraries linked dynamically when building FIDO-enabled CLIs.
# Vendored FIDO/OPAQUE archives are linked statically via cli_fido_cgo_ldflags().
fido_cgo_os_dynamic_libs() {
    detect_build_platform
    case "$BUILD_OS" in
        linux)
            echo "-ludev -lpthread"
            ;;
        freebsd|openbsd)
            echo "-lpthread"
            ;;
        darwin)
            echo "-framework CoreFoundation -framework IOKit"
            ;;
        *)
            echo "-lpthread"
            ;;
    esac
}

# Backward-compatible alias used by build-libfido2.sh logging.
fido_cgo_extra_libs() {
    fido_cgo_os_dynamic_libs
}

# Documented Linux CLI runtime dynamic dependencies (for verify + future release notes).
cli_linux_dynamic_runtime_libs() {
    echo "libudev libc libpthread libdl libresolv"
}

# CGO CFLAGS for OPAQUE-only binaries (server).
opaque_cgo_cflags() {
    echo "-I./${LIBOPAQUE_SRC} -I./${LIBOPRF_SRC} -I./${LIBSODIUM_INCLUDE}"
}

# CGO LDFLAGS for OPAQUE-only binaries (server, fully static via server_go_ldflags).
opaque_cgo_ldflags() {
    local repo_root="${1:-.}"
    repo_root="$(cd "$repo_root" && pwd)"
    echo "-L./${LIBOPAQUE_SRC} -L./${LIBOPRF_SRC} -lopaque -loprf ${repo_root}/${LIBSODIUM_A}"
}

# Go -ldflags for the server binary (fully static).
server_go_ldflags() {
    echo '-s -w -buildid= -extldflags "-static"'
}

# Go -ldflags for FIDO-enabled CLIs (vendored C static; OS libs dynamic).
cli_go_ldflags() {
    echo '-s -w -buildid='
}

# CGO CFLAGS for FIDO-enabled CLIs.
cli_fido_cgo_cflags() {
    echo "$(opaque_cgo_cflags) -I./clictap -I${FIDO_PREFIX}/include"
}

# CGO LDFLAGS for FIDO-enabled CLIs: static vendored bucket, dynamic OS bucket.
cli_fido_cgo_ldflags() {
    local repo_root="${1:-.}"
    repo_root="$(cd "$repo_root" && pwd)"
    local os_dynamic
    os_dynamic="$(fido_cgo_os_dynamic_libs)"
    echo "-Wl,-Bstatic -L./${LIBOPAQUE_SRC} -L./${LIBOPRF_SRC} -lopaque -loprf ${repo_root}/${LIBSODIUM_A} -L${FIDO_PREFIX}/lib -lfido2 -lcbor -lcrypto -lz -Wl,-Bdynamic ${os_dynamic}"
}

# Verify the server binary is fully static.
verify_server_binary_static() {
    local binary="$1"
    local base

    if [ ! -f "$binary" ]; then
        echo "[X] Binary not found: $binary" >&2
        return 1
    fi

    base="$(basename "$binary")"

    if [ "$(uname -s)" = "Linux" ]; then
        if file "$binary" | grep -qi 'statically linked'; then
            echo "[OK] ${base}: static binary verified"
            return 0
        fi
        if ldd "$binary" 2>&1 | grep -qi 'not a dynamic executable'; then
            echo "[OK] ${base}: static binary verified"
            return 0
        fi
        echo "[X] ${base}: dynamic linking detected (server must be fully static)" >&2
        ldd "$binary" 2>&1 || true
        return 1
    fi

    if [[ "$OSTYPE" == "freebsd"* ]] || [[ "$OSTYPE" == "openbsd"* ]]; then
        if file "$binary" | grep -q "statically linked"; then
            echo "[OK] ${base}: static binary verified"
            return 0
        fi
        echo "[X] ${base}: dynamic linking detected" >&2
        return 1
    fi

    echo "[X] ${base}: dynamic linking detected (server must be fully static)" >&2
    return 1
}

# Verify CLI binaries: vendored libs embedded, OS libs (e.g. libudev) may be dynamic.
verify_cli_binary_linking() {
    local binary="$1"
    local base ldd_out line libname

    if [ ! -f "$binary" ]; then
        echo "[X] Binary not found: $binary" >&2
        return 1
    fi

    base="$(basename "$binary")"

    if ! command -v ldd >/dev/null 2>&1; then
        if file "$binary" | grep -q "dynamically linked"; then
            echo "[OK] ${base}: CLI linking verified (dynamic OS libs expected on this platform)"
            return 0
        fi
        echo "[OK] ${base}: static CLI binary verified"
        return 0
    fi

    ldd_out="$(ldd "$binary" 2>&1)" || true

    if echo "$ldd_out" | grep -q "not a dynamic executable"; then
        echo "[OK] ${base}: fully static CLI binary verified"
        return 0
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            *"not a dynamic executable"*) continue ;;
            *"statically linked"*) continue ;;
        esac
        libname="$(echo "$line" | awk '{print $1}' | tr -d '[:space:]')"
        [ -z "$libname" ] && continue
        libname="${libname##*/}"
        case "$libname" in
            linux-vdso.so.*|ld-linux*.so.*|ld-musl*.so.*|libc.so.*|libc.musl*.so.*|libudev.so.*|libpthread.so.*|libdl.so.*|libresolv.so.*|libm.so.*|libgcc_s.so.*)
                ;;
            libfido2.so*|libcbor.so*|libcrypto.so*|libssl.so*|libsodium.so*|libz.so.*|libopaque.so*)
                echo "[X] ${base}: unexpected dynamic dependency: ${libname}" >&2
                echo "    Vendored libraries must be statically linked into CLI binaries." >&2
                return 1
                ;;
            *)
                echo "[X] ${base}: unexpected dynamic dependency: ${libname}" >&2
                echo "    If this OS library is required at runtime, add it to cli_linux_dynamic_runtime_libs()." >&2
                return 1
                ;;
        esac
    done <<< "$ldd_out"

    echo "[OK] ${base}: CLI linking verified (vendored libs static; OS libs dynamic)"
    return 0
}

# Debian / RHEL / Alpine / Arch for package-manager hints.
detect_package_os_family() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

# Linux libudev development package name (libfido2 build + CLI runtime).
fido_udev_dev_package_name() {
    case "$(detect_package_os_family)" in
        debian) echo "libudev-dev" ;;
        rhel)   echo "systemd-devel" ;;
        alpine) echo "eudev-dev" ;;
        arch)   echo "systemd" ;;
        *)      echo "libudev-dev" ;;
    esac
}

# pkg-config search path for vendored FIDO static dependencies only.
# Host PKG_CONFIG_PATH is intentionally excluded so system libcrypto/zlib are not
# selected over the vendored static archives.
# Prefer lib/ (forced install layout); include lib64/ as a fallback for partial
# caches from RHEL/Alma cmake defaults before normalize_fido_libdir runs.
fido_pkg_config_path() {
    local paths=""
    local dir

    for dir in \
        "${FIDO_PREFIX}/lib/pkgconfig" \
        "${FIDO_PREFIX}/lib64/pkgconfig" \
        "${FIDO_PREFIX}/share/pkgconfig"
    do
        if [ -d "$dir" ]; then
            if [ -n "$paths" ]; then
                paths="${paths}:${dir}"
            else
                paths="${dir}"
            fi
        fi
    done
    echo "$paths"
}

# Write libcrypto.pc so libfido2 finds the vendored archive (not system OpenSSL).
write_fido_libcrypto_pc() {
    local prefix="$1"
    local version="${2:-3.0.15}"

    mkdir -p "${prefix}/lib/pkgconfig"
    cat >"${prefix}/lib/pkgconfig/libcrypto.pc" <<EOF
prefix=${prefix}
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: OpenSSL-libcrypto
Description: OpenSSL cryptography library (vendored static build)
Version: ${version}
Libs: -L\${libdir} -lcrypto -pthread -ldl
Cflags: -I\${includedir}
EOF
}

# emsdk (libopaque WASM) requires Python 3.10+. Alma/RHEL 9 ship python3 as 3.9.
EMSDK_MIN_PYTHON_MAJOR=3
EMSDK_MIN_PYTHON_MINOR=10

# Return 0 if $1 is an executable Python >= EMSDK_MIN_PYTHON_*.
python_meets_emsdk_min() {
    local py="$1"
    local ver major minor

    [ -n "$py" ] || return 1
    if [ ! -x "$py" ] && ! command -v "$py" >/dev/null 2>&1; then
        return 1
    fi

    ver=$("$py" -c 'import sys; print("%d %d" % (sys.version_info[0], sys.version_info[1]))' 2>/dev/null) || return 1
    # shellcheck disable=SC2086
    set -- $ver
    major="${1:-}"
    minor="${2:-}"
    [ -n "$major" ] && [ -n "$minor" ] || return 1

    if [ "$major" -gt "$EMSDK_MIN_PYTHON_MAJOR" ]; then
        return 0
    fi
    if [ "$major" -eq "$EMSDK_MIN_PYTHON_MAJOR" ] && [ "$minor" -ge "$EMSDK_MIN_PYTHON_MINOR" ]; then
        return 0
    fi
    return 1
}

# Print absolute path of a Python suitable for emsdk, or return 1.
# Honors EMSDK_PYTHON when already set and valid; otherwise prefers
# python3.13 .. python3.10, then python3 if new enough.
find_emsdk_python() {
    local candidate path

    if [ -n "${EMSDK_PYTHON:-}" ]; then
        if [ -x "$EMSDK_PYTHON" ] && python_meets_emsdk_min "$EMSDK_PYTHON"; then
            echo "$EMSDK_PYTHON"
            return 0
        fi
        if path="$(command -v "$EMSDK_PYTHON" 2>/dev/null)" && python_meets_emsdk_min "$path"; then
            echo "$path"
            return 0
        fi
    fi

    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if path="$(command -v "$candidate" 2>/dev/null)" && python_meets_emsdk_min "$path"; then
            echo "$path"
            return 0
        fi
    done

    for candidate in \
        /usr/bin/python3.13 \
        /usr/bin/python3.12 \
        /usr/bin/python3.11 \
        /usr/bin/python3.10 \
        /usr/local/bin/python3.13 \
        /usr/local/bin/python3.12 \
        /usr/local/bin/python3.11 \
        /usr/local/bin/python3.10
    do
        if [ -x "$candidate" ] && python_meets_emsdk_min "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

# Export EMSDK_PYTHON to a suitable interpreter. Return 1 if none found.
ensure_emsdk_python() {
    local py

    if ! py="$(find_emsdk_python)"; then
        return 1
    fi
    export EMSDK_PYTHON="$py"
    return 0
}

# Package name / install token for MISSING_DEPS and hints.
emsdk_python_package_name() {
    case "$(detect_package_os_family)" in
        debian) echo "python3" ;;
        rhel)   echo "python3.11" ;;
        alpine) echo "python3" ;;
        arch)   echo "python" ;;
        *)      echo "python3.11" ;;
    esac
}

print_emsdk_python_install_hint() {
    echo "    Python ${EMSDK_MIN_PYTHON_MAJOR}.${EMSDK_MIN_PYTHON_MINOR}+ is required for emsdk (libopaque WASM)."
    case "$(detect_package_os_family)" in
        debian)
            echo "      Debian/Ubuntu: apt install -y python3  # 3.10+ on Debian 12 / Ubuntu 22.04+"
            ;;
        rhel)
            echo "      RHEL/Alma/Rocky 9: dnf install -y python3.11  # system python3 is 3.9 and will not work"
            echo "      Fedora:            dnf install -y python3"
            ;;
        alpine)
            echo "      Alpine: apk add --no-cache python3"
            ;;
        arch)
            echo "      Arch: pacman -S --needed python"
            ;;
        *)
            echo "      Install a Python ${EMSDK_MIN_PYTHON_MAJOR}.${EMSDK_MIN_PYTHON_MINOR}+ interpreter (e.g. python3.11)"
            ;;
    esac
}

print_native_build_deps_hint() {
    echo "    FIDO/CLI build host packages (vendored libfido2 stack):"
    echo "      Debian/Ubuntu: apt install -y build-essential cmake pkg-config perl git libudev-dev python3"
    echo "      Alpine:        apk add --no-cache build-base cmake pkgconf-dev perl git linux-headers eudev-dev python3"
    echo "      RHEL/Alma/Rocky/Fedora: dnf install -y gcc gcc-c++ make cmake pkgconf perl git systemd-devel python3.11"
    echo "      Arch:          pacman -S --needed base-devel cmake pkgconf perl git systemd python"
    echo "      FreeBSD:       pkg install cmake gmake perl5 git pkgconf python3"
    echo "      OpenBSD:       pkg_add cmake gmake perl git python3"
    echo "    Linux CLI runtime (USB security keys): libudev/eudev userland (usually already installed)."
    print_emsdk_python_install_hint
}

print_native_build_package_install_hint() {
    case "$(detect_package_os_family)" in
        debian)
            echo "  Install with: sudo apt install -y build-essential cmake pkg-config perl git libudev-dev python3"
            ;;
        rhel)
            echo "  Install with: sudo dnf install -y gcc gcc-c++ make cmake pkgconf perl git systemd-devel python3.11"
            ;;
        alpine)
            echo "  Install with: sudo apk add --no-cache build-base cmake pkgconf-dev perl git linux-headers eudev-dev python3"
            ;;
        arch)
            echo "  Install with: sudo pacman -S --needed base-devel cmake pkgconf perl git systemd python"
            ;;
        *)
            print_native_build_deps_hint
            return
            ;;
    esac
    print_emsdk_python_install_hint
}

fido_platform_stamp() {
    local openssl_target
    detect_build_platform
    if ! openssl_target="$(detect_openssl_configure_target)"; then
        openssl_target="unsupported"
    fi
    echo "${BUILD_PLATFORM}:${openssl_target}"
}

fido_cache_valid() {
    if [ ! -f "$FIDO_LIB" ]; then
        return 1
    fi
    if [ ! -f "$FIDO_BUILD_STAMP_FILE" ]; then
        return 1
    fi
    if [ "$(cat "$FIDO_BUILD_STAMP_FILE" 2>/dev/null)" != "$(fido_platform_stamp)" ]; then
        return 1
    fi
    if ! file "$FIDO_LIB" 2>/dev/null | grep -q "archive"; then
        return 1
    fi
    return 0
}

# =============================================================================
# GO TOOLCHAIN FUNCTIONS
# =============================================================================

# POSIX-compatible Go detection with fallbacks
find_go_binary() {
    # Try command -v first (respects PATH, aliases, functions)
    if command -v go >/dev/null 2>&1; then
        command -v go
        return 0
    fi
    
    # Fallback to common installation paths
    local go_candidates=(
        "/usr/bin/go"                       # Linux package managers
        "/usr/local/bin/go"                 # BSD package managers  
        "/usr/local/go/bin/go"              # Manual golang.org installs
    )
    
    for go_path in "${go_candidates[@]}"; do
        if [ -x "$go_path" ]; then
            echo "$go_path"
            return 0
        fi
    done
    
    return 1
}

# Fix ownership of Go-related files when running as root via sudo
fix_go_ownership() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" go.mod go.sum 2>/dev/null || true
        [ -d "vendor" ] && chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
        [ -d "vendor_c" ] && chown -R "$SUDO_USER:$SUDO_USER" vendor_c/ 2>/dev/null || true
        [ -f ".vendor_cache" ] && chown "$SUDO_USER:$SUDO_USER" .vendor_cache 2>/dev/null || true
        [ -d "$BUILD_ROOT" ] && chown -R "$SUDO_USER:$SUDO_USER" "$BUILD_ROOT/" 2>/dev/null || true
    fi
}

# Run Go commands with proper user context (non-root when called via sudo)
run_go_as_user() {
    if [ -z "$GO_BINARY" ]; then
        echo "ERROR: GO_BINARY not set. Call find_go_binary first." >&2
        return 1
    fi
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H env "GOTOOLCHAIN=${GOTOOLCHAIN:-auto}" "$GO_BINARY" "$@"
    else
        "$GO_BINARY" "$@"
    fi
}

print_go_vendor_sync_hint() {
    echo "    Fix with (from the Arkfile repo root, using Go matching go.mod):"
    echo "      go mod tidy && go mod vendor && sha256sum go.sum | awk '{print \$1}' > .vendor_cache"
}

# Fail fast if go.mod disagrees with vendor/ (same rules as go build -mod=vendor).
# Call after GO_BINARY is set, before expensive WASM/FIDO/TS work.
# Returns 0 on success; prints [X] diagnostics and returns 1 on failure.
verify_go_mod_vendor_consistency() {
    local required_version list_out

    if [ -z "${GO_BINARY:-}" ]; then
        if ! GO_BINARY="$(find_go_binary)"; then
            echo "[X] Go compiler not found; cannot verify vendor consistency" >&2
            return 1
        fi
        export GO_BINARY
    fi

    if [ ! -f go.mod ]; then
        echo "[X] go.mod missing; run this check from the Arkfile repo root" >&2
        return 1
    fi
    if [ ! -d vendor ] || [ ! -f vendor/modules.txt ]; then
        echo "[X] vendor/ is missing or incomplete (need vendor/modules.txt before -mod=vendor builds)" >&2
        print_go_vendor_sync_hint
        return 1
    fi
    if [ ! -f go.sum ]; then
        echo "[X] go.sum is missing" >&2
        print_go_vendor_sync_hint
        return 1
    fi

    required_version="$(grep '^go [0-9]' go.mod | awk '{print $2}')"
    if [ -n "$required_version" ]; then
        export GOTOOLCHAIN="${GOTOOLCHAIN:-go${required_version}+auto}"
    fi

    # Cheap probe (seconds): same consistency rules as go build -mod=vendor.
    # Note: `go list -m all` is not supported with -mod=vendor; list packages instead.
    if ! list_out="$(run_go_as_user list -mod=vendor ./... 2>&1)"; then
        echo "[X] go.mod and vendor/ are out of sync (inconsistent vendoring)" >&2
        echo "$list_out" | head -n 25 >&2
        print_go_vendor_sync_hint
        return 1
    fi

    echo "[OK] go.mod and vendor/ are consistent (-mod=vendor)"
    return 0
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Ensure build directory exists with correct ownership
ensure_build_dir() {
    mkdir -p "$BUILD_ROOT" "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_CLIBS" \
             "$BUILD_WASM" "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT" \
             "$BUILD_CLIENT_JS_DIST"
    
    # If running as root via sudo, set ownership to the original user
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$BUILD_ROOT" 2>/dev/null || true
    fi
    
    echo "[OK] Build directory ready: $BUILD_ROOT"
}

# Clean build directory (preserves C libs by default for faster rebuilds)
clean_build_dir() {
    local clean_all="${1:-false}"
    
    if [ "$clean_all" = "true" ] || [ "$clean_all" = "--all" ]; then
        echo "[CLEAN] Removing entire build directory: $BUILD_ROOT"
        rm -rf "$BUILD_ROOT"
    else
        echo "[CLEAN] Cleaning build artifacts (preserving C libs for faster rebuilds)"
        rm -rf "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_WASM" \
               "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT"
        rm -f "$BUILD_ROOT/version.json"
    fi
}

# Check if C libraries exist and are valid.
# Also verifies vendored libsodium static archive.
c_libs_exist() {
    if [ -f "$LIBOPAQUE_A" ] && [ -f "$LIBOPRF_A" ] && [ -f "$LIBSODIUM_A" ]; then
        # Verify they're actual archive files
        if file "$LIBOPAQUE_A" | grep -q "archive" && \
           file "$LIBOPRF_A" | grep -q "archive" && \
           file "$LIBSODIUM_A" | grep -q "archive"; then
            return 0
        fi
    fi
    return 1
}

# Check if WASM files exist
wasm_exists() {
    if [ -f "$BUILD_WASM/libopaque.js" ]; then
        return 0
    fi
    return 1
}

# Print build configuration (for debugging)
print_build_config() {
    echo "=== Arkfile Build Configuration ==="
    echo "BUILD_ROOT:      $BUILD_ROOT"
    echo "BUILD_BIN:       $BUILD_BIN"
    echo "BUILD_CLIENT:    $BUILD_CLIENT"
    echo "BUILD_CLIBS:     $BUILD_CLIBS"
    echo "BUILD_WASM:      $BUILD_WASM"
    echo "BUILD_EMSDK:     $BUILD_EMSDK"
    echo "==================================="
}

init_fido_paths

# Export the script directory for relative path resolution
if [ -n "$BASH_SOURCE" ]; then
    export BUILD_CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # POSIX fallback
    export BUILD_CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
