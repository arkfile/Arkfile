#!/bin/bash
# Cross-platform vendored static build for CLI FIDO2 (libfido2 + libcbor + zlib + libcrypto).
#
# Produces static archives under $BUILD_CLIBS/fido for arkfile-client and arkfile-admin.
# The arkfile server binary does not link this stack.
#
# Host tools required (no preinstalled libfido2/openssl packages):
#   - cmake, gcc/clang (or compatible C compiler)
#   - make or gmake (BSDs)
#   - perl (OpenSSL Configure)
#   - pkg-config (libfido2 discovers vendored libcbor/zlib/libcrypto)
#   - git (on-demand source clone when vendor trees are absent)
#   - Linux: libudev development headers (libudev.pc) for libfido2 configure
#
# Platform-specific runtime deps for the final CLI link step are handled separately
# via fido_cgo_extra_libs() in build-config.sh (e.g. -ludev on Linux).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build-config.sh
source "$SCRIPT_DIR/build-config.sh"

LIBFIDO2_VERSION="${LIBFIDO2_VERSION:-1.14.0}"
LIBCBOR_VERSION="${LIBCBOR_VERSION:-0.11.0}"
ZLIB_VERSION="${ZLIB_VERSION:-1.3.1}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.0.15}"

FIDO_VENDOR="${VENDOR_C_ROOT}/yubico"
FIDO_SRC="${FIDO_VENDOR}/libfido2"
CBOR_SRC="${FIDO_VENDOR}/libcbor"
ZLIB_SRC="${VENDOR_C_ROOT}/madler/zlib"
OPENSSL_SRC="${VENDOR_C_ROOT}/openssl/openssl"

JOBS="${JOBS:-$(get_parallel_jobs)}"
MAKE_CMD=""
OPENSSL_TARGET=""
OPENSSL_EXTRA_CONFIG=""
CMAKE_EXTRA_ARGS=()

# =============================================================================
# Toolchain checks
# =============================================================================

require_cmake() {
    if ! command -v cmake >/dev/null 2>&1; then
        echo "[X] cmake is required to build libfido2"
        print_native_build_deps_hint
        exit 1
    fi
}

require_perl() {
    if ! command -v perl >/dev/null 2>&1; then
        echo "[X] perl is required to configure vendored OpenSSL"
        print_native_build_deps_hint
        exit 1
    fi
}

require_git() {
    if ! command -v git >/dev/null 2>&1; then
        echo "[X] git is required to fetch vendored FIDO2 sources when absent"
        print_native_build_deps_hint
        exit 1
    fi
}

require_cc() {
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        echo "[X] A C compiler (cc/gcc) is required"
        print_native_build_deps_hint
        exit 1
    fi
}

require_pkg_config() {
    if ! command -v pkg-config >/dev/null 2>&1; then
        echo "[X] pkg-config is required to configure libfido2 against vendored deps"
        print_native_build_deps_hint
        exit 1
    fi
}

require_linux_udev_dev() {
    detect_build_platform
    [ "$BUILD_OS" = "linux" ] || return 0

    if pkg-config --exists libudev 2>/dev/null; then
        return 0
    fi

    echo "[X] libudev development files are required to build libfido2 on Linux"
    echo "    Install: $(fido_udev_dev_package_name) (provides libudev.pc)"
    print_native_build_deps_hint
    exit 1
}

install_fido_zlib_pc() {
    if [ -f "${FIDO_PREFIX}/share/pkgconfig/zlib.pc" ]; then
        mkdir -p "${FIDO_PREFIX}/lib/pkgconfig"
        cp "${FIDO_PREFIX}/share/pkgconfig/zlib.pc" "${FIDO_PREFIX}/lib/pkgconfig/zlib.pc"
    fi
}

verify_fido_pkg_config() {
    local module
    local failed=0

    export PKG_CONFIG_PATH="$(fido_pkg_config_path)"
    echo "[INFO] PKG_CONFIG_PATH=${PKG_CONFIG_PATH}"

    for module in libcbor libcrypto zlib; do
        if pkg-config --exists "$module" 2>/dev/null; then
            echo "[OK] pkg-config: ${module} ($(pkg-config --modversion "$module" 2>/dev/null || echo unknown))"
        else
            echo "[X] pkg-config cannot find vendored ${module}"
            failed=1
        fi
    done

    if [ "$failed" -ne 0 ]; then
        echo "[X] Vendored FIDO dependency .pc files are missing or incomplete"
        ls -la "${FIDO_PREFIX}/lib/pkgconfig" 2>/dev/null || true
        return 1
    fi
    return 0
}

detect_platform() {
    detect_build_platform

    if ! MAKE_CMD="$(find_make_command)"; then
        echo "[X] No make command found (tried: gmake, make)"
        print_native_build_deps_hint
        exit 1
    fi

    if ! OPENSSL_TARGET="$(detect_openssl_configure_target)"; then
        echo "[X] Unsupported build platform for vendored OpenSSL: $(uname -s)/$(uname -m)"
        exit 1
    fi

    if is_linux_musl; then
        # musl/Alpine: disable Linux-only OpenSSL features that assume glibc.
        OPENSSL_EXTRA_CONFIG="no-afalgeng no-async"
        echo "[INFO] musl libc detected; OpenSSL extra config: ${OPENSSL_EXTRA_CONFIG}"
    fi

    case "$BUILD_OS" in
        linux|freebsd|openbsd|darwin)
            ;;
        *)
            echo "[X] Unsupported OS for CLI FIDO2 build: ${BUILD_OS} ($(uname -s))"
            echo "    Supported: Linux, FreeBSD, OpenBSD, Darwin"
            exit 1
            ;;
    esac

    echo "[INFO] Build platform: ${BUILD_PLATFORM} ($(uname -s)/$(uname -m))"
    echo "[INFO] OpenSSL Configure target: ${OPENSSL_TARGET}"
    echo "[INFO] Using make command: ${MAKE_CMD}"
    echo "[INFO] Parallel jobs: ${JOBS}"
}

# =============================================================================
# Source acquisition
# =============================================================================

clone_tag() {
    local url="$1"
    local dest="$2"
    local tag="$3"

    if [ -d "$dest/.git" ] || [ -f "$dest/CMakeLists.txt" ] || [ -f "$dest/configure" ]; then
        echo "[OK] Source present: $dest"
        return 0
    fi

    require_git
    echo "[INFO] Cloning $url ($tag) into $dest..."
    mkdir -p "$(dirname "$dest")"
    git clone --depth 1 --branch "$tag" "$url" "$dest"
}

# =============================================================================
# Cache / stamp
# =============================================================================

write_fido_build_stamp() {
    mkdir -p "$FIDO_PREFIX"
    fido_platform_stamp >"$FIDO_BUILD_STAMP_FILE"
    echo "[OK] Recorded FIDO build stamp: $(cat "$FIDO_BUILD_STAMP_FILE")"
}

invalidate_fido_cache() {
    if [ -d "$FIDO_PREFIX" ]; then
        echo "[INFO] Clearing stale FIDO2 install prefix: $FIDO_PREFIX"
        rm -rf "$FIDO_PREFIX"
    fi
    rm -rf "${BUILD_CLIBS}/zlib-build" \
           "${BUILD_CLIBS}/openssl-build" \
           "${BUILD_CLIBS}/libcbor-build" \
           "${BUILD_CLIBS}/libfido2-build"
}

ensure_fido_cache_fresh() {
    if fido_cache_valid; then
        echo "[OK] FIDO2 static libraries already built for this platform: $FIDO_LIB"
        return 0
    fi

    if [ -f "$FIDO_LIB" ] || [ -f "$FIDO_BUILD_STAMP_FILE" ]; then
        echo "[WARNING] FIDO2 cache missing or built for a different platform; rebuilding..."
        invalidate_fido_cache
    fi
    return 1
}

# =============================================================================
# Component builds
# =============================================================================

build_zlib() {
    local out="${FIDO_PREFIX}/lib/libz.a"
    if [ -f "$out" ]; then
        echo "[OK] libz.a exists"
        install_fido_zlib_pc
        return 0
    fi

    clone_tag "https://github.com/madler/zlib.git" "$ZLIB_SRC" "v${ZLIB_VERSION}"

    local build_dir="${BUILD_CLIBS}/zlib-build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "[BUILD] zlib..."
    (
        cd "$build_dir"
        cmake "$OLDPWD/$ZLIB_SRC" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DCMAKE_INSTALL_PREFIX="$FIDO_PREFIX"
        cmake --build . --parallel "$JOBS"
        cmake --install .
    )
    install_fido_zlib_pc
}

build_openssl() {
    local out="${FIDO_PREFIX}/lib/libcrypto.a"
    if [ -f "$out" ]; then
        echo "[OK] libcrypto.a exists"
        write_fido_libcrypto_pc "$FIDO_PREFIX" "$OPENSSL_VERSION"
        return 0
    fi

    clone_tag "https://github.com/openssl/openssl.git" "$OPENSSL_SRC" "openssl-${OPENSSL_VERSION}"

    local build_dir="${BUILD_CLIBS}/openssl-build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "[BUILD] OpenSSL libcrypto (${OPENSSL_TARGET})..."
    (
        cd "$build_dir"
        # shellcheck disable=SC2086
        "$OLDPWD/$OPENSSL_SRC/Configure" "$OPENSSL_TARGET" \
            --prefix="$FIDO_PREFIX" \
            --libdir=lib \
            no-shared no-ssl3 no-engine no-dso no-ui-console no-tests \
            $OPENSSL_EXTRA_CONFIG
        # build_generated must finish before libcrypto.a: parallel make races on
        # generated include/openssl/*.h and produces macro parse errors.
        "$MAKE_CMD" build_generated
        "$MAKE_CMD" -j"$JOBS" libcrypto.a
        mkdir -p "$FIDO_PREFIX/lib" "$FIDO_PREFIX/include/openssl"
        cp libcrypto.a "$FIDO_PREFIX/lib/"
        # Public headers: static .h from source + generated .h from build tree.
        cp "$OLDPWD/$OPENSSL_SRC/include/openssl/"*.h "$FIDO_PREFIX/include/openssl/" 2>/dev/null || true
        cp include/openssl/*.h "$FIDO_PREFIX/include/openssl/"
        if [ -d include/crypto ]; then
            mkdir -p "$FIDO_PREFIX/include/crypto"
            cp include/crypto/*.h "$FIDO_PREFIX/include/crypto/" 2>/dev/null || true
        fi
        write_fido_libcrypto_pc "$FIDO_PREFIX" "$OPENSSL_VERSION"
    )
}

build_libcbor() {
    local out="${FIDO_PREFIX}/lib/libcbor.a"
    if [ -f "$out" ]; then
        echo "[OK] libcbor.a exists"
        return 0
    fi

    clone_tag "https://github.com/PJK/libcbor.git" "$CBOR_SRC" "v${LIBCBOR_VERSION}"

    local build_dir="${BUILD_CLIBS}/libcbor-build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "[BUILD] libcbor..."
    (
        cd "$build_dir"
        cmake "$OLDPWD/$CBOR_SRC" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DCMAKE_INSTALL_PREFIX="$FIDO_PREFIX" \
            "${CMAKE_EXTRA_ARGS[@]}"
        cmake --build . --parallel "$JOBS"
        cmake --install .
    )
}

build_libfido2() {
    local out="${FIDO_PREFIX}/lib/libfido2.a"
    if [ -f "$out" ]; then
        echo "[OK] libfido2.a exists"
        return 0
    fi

    clone_tag "https://github.com/Yubico/libfido2.git" "$FIDO_SRC" "${LIBFIDO2_VERSION}"

    local build_dir="${BUILD_CLIBS}/libfido2-build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "[BUILD] libfido2..."
    require_linux_udev_dev
    if ! verify_fido_pkg_config; then
        exit 1
    fi
    (
        cd "$build_dir"
        export PKG_CONFIG_PATH="$(fido_pkg_config_path)"
        cmake "$OLDPWD/$FIDO_SRC" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_EXAMPLES=OFF \
            -DBUILD_MANPAGES=OFF \
            -DBUILD_TOOLS=OFF \
            -DCMAKE_INSTALL_PREFIX="$FIDO_PREFIX" \
            -DCRYPTO_BACKEND=openssl \
            "${CMAKE_EXTRA_ARGS[@]}"
        cmake --build . --parallel "$JOBS"
        cmake --install .
    )
}

verify_fido_libraries() {
    local libs=(
        "${FIDO_PREFIX}/lib/libz.a"
        "${FIDO_PREFIX}/lib/libcrypto.a"
        "${FIDO_PREFIX}/lib/libcbor.a"
        "${FIDO_PREFIX}/lib/libfido2.a"
    )
    local lib

    for lib in "${libs[@]}"; do
        if [ ! -f "$lib" ]; then
            echo "[X] Missing expected archive: $lib"
            return 1
        fi
        if ! file "$lib" 2>/dev/null | grep -q "archive"; then
            echo "[X] Not a static archive: $lib"
            return 1
        fi
    done

    echo "[FILES] FIDO2 static libraries verified:"
    ls -la "${libs[@]}"
    return 0
}

# =============================================================================
# Main
# =============================================================================

main() {
    local script_start_dir
    script_start_dir="$(pwd)"

    echo "Arkfile FIDO2 static library build (cross-platform)"

    require_cmake
    require_perl
    require_pkg_config
    require_cc
    detect_platform

    if ensure_fido_cache_fresh; then
        exit 0
    fi

    ensure_build_dir
    mkdir -p "${FIDO_PREFIX}/lib" "${FIDO_PREFIX}/include"

    build_zlib
    build_openssl
    build_libcbor
    build_libfido2

    cd "$script_start_dir"

    if ! verify_fido_libraries; then
        echo "[X] FIDO2 static library verification failed"
        exit 1
    fi

    write_fido_build_stamp
    echo "[OK] FIDO2 static libraries installed under ${FIDO_PREFIX}"
    echo "[INFO] CLI OS dynamic libs for this host: $(fido_cgo_os_dynamic_libs)"
}

main "$@"
