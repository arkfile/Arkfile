#!/bin/bash
# Cross-platform static library build system
#
# libsodium is vendored from source under
# vendor_c/jedisct1/libsodium. This script:
#   1. Builds vendored libsodium statically (./configure && make).
#   2. Builds noise_xk, liboprf, libopaque statically against the vendored
#      libsodium include path and static archive.
#
# No host libsodium package is installed or consulted -- pkg-config is no
# longer used for libsodium discovery. Tools required on the build host:
#   - gcc (or compatible C compiler)
#   - make (or gmake on BSDs)
#   - autoconf, automake, libtool (for libsodium's autotools build)
#
# Build artifacts live in-tree under each vendor submodule's own layout and
# are excluded from version control via .gitignore.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build-config.sh
source "$SCRIPT_DIR/build-config.sh"

echo "Arkfile Static Library Build System (vendored libsodium)"

# =============================================================================
# Tool detection
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

# Verify the autotools toolchain that libsodium's ./autogen.sh needs.
# Failing here gives a clearer error than letting autogen.sh die mid-stream.
require_autotools() {
    local missing=""
    for tool in autoconf automake libtoolize; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            # libtoolize is sometimes named glibtoolize (macOS, BSDs)
            if [ "$tool" = "libtoolize" ] && command -v glibtoolize >/dev/null 2>&1; then
                continue
            fi
            missing="$missing $tool"
        fi
    done
    if [ -n "$missing" ]; then
        echo "[X] Missing autotools required for libsodium build:$missing"
        echo "    Install via your OS package manager:"
        echo "      Debian/Ubuntu: apt install autoconf automake libtool make gcc"
        echo "      Alpine:        apk add autoconf automake libtool make gcc musl-dev"
        echo "      RHEL/AlmaLinux: dnf install autoconf automake libtool make gcc"
        echo "      Arch:          pacman -S autoconf automake libtool make gcc"
        echo "      FreeBSD:       pkg install autoconf automake libtool gmake gcc"
        return 1
    fi
    return 0
}

# POSIX-compatible Go detection with fallbacks
find_go_binary() {
    if command -v go >/dev/null 2>&1; then
        command -v go
        return 0
    fi
    local go_candidates=(
        "/usr/bin/go"
        "/usr/local/bin/go"
        "/usr/local/go/bin/go"
    )
    for go_path in "${go_candidates[@]}"; do
        if [ -x "$go_path" ]; then
            echo "$go_path"
            return 0
        fi
    done
    return 1
}

check_go_version() {
    local required_major=1
    local required_minor=26

    local go_binary
    if ! go_binary=$(find_go_binary); then
        echo "[X] Go compiler not found in standard locations"
        echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
        echo "   Please install Go 1.26+ from your package manager or https://golang.org"
        exit 1
    fi

    echo "[OK] Found Go at: $go_binary"

    local current_version=$("$go_binary" version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    local current_major=$(echo $current_version | cut -d. -f1)
    local current_minor=$(echo $current_version | cut -d. -f2)

    if [ "$current_major" -lt "$required_major" ] ||
       ([ "$current_major" -eq "$required_major" ] && [ "$current_minor" -lt "$required_minor" ]); then
        echo "[X] Go version $current_version is too old"
        echo "Required: Go ${required_major}.${required_minor}+ (from go.mod)"
        exit 1
    fi

    echo "[OK] Go version $current_version meets requirements (>= ${required_major}.${required_minor})"
}

# =============================================================================
# Vendored libsodium build
# =============================================================================

# Path to the vendored libsodium submodule (relative to repo root).
# Kept in sync with LIBSODIUM_DIR in scripts/setup/build-config.sh.
LIBSODIUM_DIR="$LIBSODIUM_DIR"
LIBSODIUM_INCLUDE_DIR="$LIBSODIUM_INCLUDE"
LIBSODIUM_STATIC_ARCHIVE="$LIBSODIUM_A"

build_libsodium_vendored() {
    echo "[BUILD] Building vendored libsodium statically..."

    if [ ! -d "$LIBSODIUM_DIR" ]; then
        echo "[X] Vendored libsodium directory not found: $LIBSODIUM_DIR"
        echo "    Run 'git submodule update --init --recursive' in the repo root."
        exit 1
    fi

    if [ ! -f "$LIBSODIUM_DIR/autogen.sh" ] && [ ! -f "$LIBSODIUM_DIR/configure" ]; then
        echo "[X] Vendored libsodium appears empty (no autogen.sh or configure)."
        echo "    Run 'git submodule update --init --recursive' in the repo root."
        exit 1
    fi

    # If the static archive already exists, skip the rebuild. The submodule
    # commit pin is the source of truth; once built, the artifact is reused.
    if [ -f "$LIBSODIUM_STATIC_ARCHIVE" ]; then
        if file "$LIBSODIUM_STATIC_ARCHIVE" | grep -q "archive"; then
            echo "[OK] Vendored libsodium already built: $LIBSODIUM_STATIC_ARCHIVE"
            return 0
        fi
        echo "[WARNING] Existing libsodium.a is not a valid archive; rebuilding..."
        rm -f "$LIBSODIUM_STATIC_ARCHIVE"
    fi

    if ! require_autotools; then
        exit 1
    fi

    (
        cd "$LIBSODIUM_DIR"

        # Regenerate autotools artifacts if configure is missing. The submodule
        # ships ./autogen.sh which produces ./configure.
        if [ ! -f "configure" ]; then
            echo "[INFO] Running autogen.sh to produce configure script..."
            ./autogen.sh -s
        fi

        # Static-only build. --disable-shared keeps libsodium.so out of the
        # tree (we only need the .a). --disable-pie is what jedisct1 itself
        # recommends when building libsodium for inclusion in other static
        # binaries; Go's `-extldflags "-static"` requires PIE-free archives
        # on most glibc-targeting platforms.
        echo "[INFO] Configuring libsodium (static-only)..."
        ./configure \
            --enable-static \
            --disable-shared \
            --disable-pie \
            --without-pthreads \
            >/dev/null

        echo "[INFO] Compiling libsodium..."
        $MAKE_CMD -j"$(nproc 2>/dev/null || echo 2)" >/dev/null
    )

    if [ ! -f "$LIBSODIUM_STATIC_ARCHIVE" ]; then
        echo "[X] libsodium build completed but $LIBSODIUM_STATIC_ARCHIVE was not produced"
        exit 1
    fi

    if ! file "$LIBSODIUM_STATIC_ARCHIVE" | grep -q "archive"; then
        echo "[X] $LIBSODIUM_STATIC_ARCHIVE is not a valid archive"
        exit 1
    fi

    echo "[OK] Vendored libsodium built: $LIBSODIUM_STATIC_ARCHIVE"
}

# =============================================================================
# Build noise_xk, liboprf, libopaque against vendored libsodium
# =============================================================================

build_static_libraries() {
    echo "[BUILD] Building static libraries in vendor/ directories..."

    # Vendored libsodium provides headers and a static archive. Compose the
    # flags the libopaque/liboprf Makefiles will consume via CFLAGS / LDFLAGS.
    local SODIUM_INCLUDE_ABS
    SODIUM_INCLUDE_ABS="$(pwd)/$LIBSODIUM_INCLUDE_DIR"

    if [ ! -d "$SODIUM_INCLUDE_ABS" ]; then
        echo "[X] Vendored libsodium include dir missing: $SODIUM_INCLUDE_ABS"
        exit 1
    fi

    # Compose CFLAGS / LDFLAGS for liboprf and libopaque builds.
    #   -I<libsodium include>      : point at vendored headers, never at host
    #   <libsodium.a path>         : static archive added to LDFLAGS directly
    export CFLAGS="-O2 -fPIC"
    export LDFLAGS="-static"

    # Vendor directories
    OPRF_DIR="$LIBOPRF_SRC"
    OPAQUE_DIR="$LIBOPAQUE_SRC"

    # Build noise_xk library first (dependency for liboprf)
    echo "Building noise_xk static library..."
    if [ ! -d "$OPRF_DIR" ]; then
        echo "[X] liboprf source directory not found: $OPRF_DIR"
        echo "    Run 'git submodule update --init --recursive' in the repo root."
        exit 1
    fi

    cd "$OPRF_DIR/noise_xk"
    $MAKE_CMD clean || true
    # Build noise_xk with its own flags but cap FORTIFY_SOURCE at 2 for GCC < 12 compatibility.
    # The noise_xk makefile uses CFLAGS ?= so we must pass CFLAGS explicitly to override it.
    NOISE_XK_CFLAGS="-Wall -Wextra -Werror -std=c11 -Wno-unused-variable \
        -Wno-unknown-warning-option -Wno-unused-but-set-variable \
        -Wno-unused-parameter -Wno-infinite-recursion -fpic \
        -fwrapv -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM \
        -O2 -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
        -fasynchronous-unwind-tables -fpic \
        -Werror=format-security -Werror=implicit-function-declaration \
        -ftrapv \
        -I$SODIUM_INCLUDE_ABS"
    $MAKE_CMD CFLAGS="$NOISE_XK_CFLAGS" AR=ar ARFLAGS=rcs liboprf-noiseXK.a

    # Build liboprf static library
    echo "Building liboprf static library..."
    cd ..
    $MAKE_CMD clean || true

    NOISE_INCLUDES="-Inoise_xk/include -Inoise_xk/include/karmel -Inoise_xk/include/karmel/minimal"

    $MAKE_CMD CFLAGS="$CFLAGS -I$SODIUM_INCLUDE_ABS $NOISE_INCLUDES" \
              LDFLAGS="$LDFLAGS -Lnoise_xk" \
              AR=ar ARFLAGS=rcs liboprf.a

    # Build libopaque static library
    echo "Building libopaque static library..."
    cd "../../libopaque/src"
    $MAKE_CMD clean || true

    # Create oprf subdirectory and symlink headers for libopaque build
    mkdir -p oprf
    ln -sf ../../../liboprf/src/toprf.h oprf/toprf.h 2>/dev/null || true
    ln -sf ../../../liboprf/src/oprf.h oprf/oprf.h 2>/dev/null || true

    $MAKE_CMD CFLAGS="$CFLAGS -I../../liboprf/src -I. -I$SODIUM_INCLUDE_ABS" \
              AR=ar ARFLAGS=rcs libopaque.a

    echo "[OK] Static libraries built successfully"
}

# Verify libraries from project root
verify_static_libraries() {
    local OPRF_LIB="$LIBOPRF_A"
    local OPAQUE_LIB="$LIBOPAQUE_A"
    local SODIUM_LIB="$LIBSODIUM_A"

    if [ -f "$OPRF_LIB" ] && [ -f "$OPAQUE_LIB" ] && [ -f "$SODIUM_LIB" ]; then
        echo "[FILES] Static libraries verified:"
        ls -la "$OPRF_LIB" "$OPAQUE_LIB" "$SODIUM_LIB"
        return 0
    else
        echo "[X] Static library verification failed"
        [ ! -f "$OPRF_LIB" ] && echo "Missing: $OPRF_LIB"
        [ ! -f "$OPAQUE_LIB" ] && echo "Missing: $OPAQUE_LIB"
        [ ! -f "$SODIUM_LIB" ] && echo "Missing: $SODIUM_LIB"
        return 1
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    local SCRIPT_START_DIR
    SCRIPT_START_DIR="$(pwd)"

    check_go_version

    # Detect make command (gmake on BSDs)
    if ! MAKE_CMD=$(find_make_command); then
        echo "[X] No make command found (tried: make, gmake)"
        exit 1
    fi
    echo "[INFO] Using make command: $MAKE_CMD"

    # Build vendored libsodium first; libopaque / liboprf depend on it.
    build_libsodium_vendored

    # Return to repo root before building libopaque / liboprf
    cd "$SCRIPT_START_DIR"

    build_static_libraries

    # Return to the starting directory for verification
    cd "$SCRIPT_START_DIR"

    if verify_static_libraries; then
        echo "[OK] Static library build completed successfully!"
    else
        echo "[X] Static library verification failed"
        exit 1
    fi
}

main "$@"
