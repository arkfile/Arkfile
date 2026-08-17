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
# Install layout: all static archives and .pc files go under ${FIDO_PREFIX}/lib
# (CMAKE_INSTALL_LIBDIR=lib / OpenSSL --libdir=lib). RHEL/Alma/Fedora cmake
# otherwise defaults to lib64, which breaks pkg-config and CGO -L paths.
#
# Platform-specific runtime deps for the final CLI link step are handled separately
# via fido_cgo_extra_libs() in build-config.sh (e.g. -ludev on Linux).

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build-config.sh
source "$SCRIPT_DIR/build-config.sh"

FIDO_VENDOR="${VENDOR_C_ROOT}/yubico"
FIDO_SRC="${FIDO_VENDOR}/libfido2"
CBOR_SRC="${FIDO_VENDOR}/libcbor"
ZLIB_SRC="${VENDOR_C_ROOT}/madler/zlib"
ZLIB_BUILD_SOURCE="${BUILD_CLIBS}/zlib-source"
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
    local perl_pkgs
    if ! command -v perl >/dev/null 2>&1; then
        echo "[X] perl is required to configure vendored OpenSSL"
        print_native_build_deps_hint
        exit 1
    fi
    perl_pkgs="$(missing_openssl_configure_perl_packages)"
    if [ -n "$perl_pkgs" ]; then
        echo "[X] OpenSSL Configure needs Perl modules not present on this host (install: ${perl_pkgs})"
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

# Move any lib64 leftovers into lib/ so CGO and pkg-config see one layout.
# Also rewrite .pc libdir lines that still point at lib64 after relocate.
normalize_fido_libdir() {
    if [ ! -d "${FIDO_PREFIX}/lib64" ]; then
        return 0
    fi

    mkdir -p "${FIDO_PREFIX}/lib" "${FIDO_PREFIX}/lib/pkgconfig"
    local f tmp
    for f in "${FIDO_PREFIX}/lib64/"*.a; do
        [ -f "$f" ] || continue
        mv -f "$f" "${FIDO_PREFIX}/lib/"
    done
    if [ -d "${FIDO_PREFIX}/lib64/pkgconfig" ]; then
        for f in "${FIDO_PREFIX}/lib64/pkgconfig/"*.pc; do
            [ -f "$f" ] || continue
            mv -f "$f" "${FIDO_PREFIX}/lib/pkgconfig/"
        done
    fi
    for f in "${FIDO_PREFIX}/lib/pkgconfig/"*.pc; do
        [ -f "$f" ] || continue
        if grep -q 'lib64' "$f" 2>/dev/null; then
            tmp="${f}.tmp"
            sed 's|/lib64|/lib|g' "$f" >"$tmp"
            mv -f "$tmp" "$f"
        fi
    done
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
        ls -la "${FIDO_PREFIX}/lib64/pkgconfig" 2>/dev/null || true
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
    local expected_commit="$4"
    local current_commit target_commit

    require_git
    if [ -d "$dest/.git" ]; then
        git -C "$dest" fetch --depth 1 origin "refs/tags/${tag}:refs/tags/${tag}" 2>/dev/null || true
        target_commit=$(git -C "$dest" rev-list -n 1 "$tag" 2>/dev/null || true)
        current_commit=$(git -C "$dest" rev-parse HEAD 2>/dev/null || true)
        if [ -z "$target_commit" ]; then
            echo "[X] Could not resolve pinned tag $tag in $dest"
            exit 1
        fi
        if [ "$target_commit" != "$expected_commit" ]; then
            echo "[X] Tag $tag resolved to $target_commit; expected $expected_commit"
            exit 1
        fi
        if [ "$current_commit" != "$target_commit" ]; then
            if [ -n "$(git -C "$dest" status --porcelain 2>/dev/null)" ]; then
                echo "[X] Refusing to replace modified source tree at $dest"
                echo "    Expected tag: $tag ($target_commit)"
                echo "    Current commit: $current_commit"
                exit 1
            fi
            echo "[INFO] Updating $dest to pinned tag $tag..."
            git -C "$dest" checkout --detach "$target_commit"
        fi
        if ! git -C "$dest" diff --quiet HEAD -- .; then
            echo "[X] Pinned source has local tracked modifications: $dest"
            exit 1
        fi
        echo "[OK] Source pin verified: $dest ($tag @ $target_commit)"
        return 0
    fi
    if [ -e "$dest" ]; then
        echo "[X] Existing source tree is not a Git clone and cannot be verified: $dest"
        exit 1
    fi

    echo "[INFO] Cloning $url ($tag) into $dest..."
    mkdir -p "$(dirname "$dest")"
    git clone --depth 1 --branch "$tag" "$url" "$dest"
    target_commit=$(git -C "$dest" rev-list -n 1 "$tag")
    current_commit=$(git -C "$dest" rev-parse HEAD)
    if [ "$target_commit" != "$expected_commit" ] || [ "$current_commit" != "$expected_commit" ]; then
        echo "[X] Cloned source does not match pinned tag and commit: $tag @ $expected_commit"
        exit 1
    fi
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
           "$ZLIB_BUILD_SOURCE" \
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

prepare_zlib_build_source() {
    require_git
    if [ -d "$ZLIB_SRC/.git" ]; then
        git -C "$ZLIB_SRC" fetch --depth 1 origin "refs/tags/v${ZLIB_VERSION}:refs/tags/v${ZLIB_VERSION}" 2>/dev/null || true
    elif [ -e "$ZLIB_SRC" ]; then
        echo "[X] Existing zlib source tree is not a Git clone: $ZLIB_SRC"
        exit 1
    else
        echo "[INFO] Cloning zlib v${ZLIB_VERSION} into $ZLIB_SRC..."
        mkdir -p "$(dirname "$ZLIB_SRC")"
        git clone --depth 1 --branch "v${ZLIB_VERSION}" "https://github.com/madler/zlib.git" "$ZLIB_SRC"
    fi

    local target_commit
    target_commit=$(git -C "$ZLIB_SRC" rev-list -n 1 "v${ZLIB_VERSION}" 2>/dev/null || true)
    if [ "$target_commit" != "$ZLIB_COMMIT" ]; then
        echo "[X] zlib tag v${ZLIB_VERSION} resolved to $target_commit; expected $ZLIB_COMMIT"
        exit 1
    fi

    rm -rf "$ZLIB_BUILD_SOURCE"
    mkdir -p "$ZLIB_BUILD_SOURCE"
    if ! git -C "$ZLIB_SRC" archive "$ZLIB_COMMIT" | tar -x -C "$ZLIB_BUILD_SOURCE"; then
        echo "[X] Failed to export pinned zlib source commit $ZLIB_COMMIT"
        exit 1
    fi
}

build_zlib() {
    local out="${FIDO_PREFIX}/lib/libz.a"
    if [ ! -f "$out" ]; then
        normalize_fido_libdir
    fi
    if [ -f "$out" ]; then
        echo "[OK] libz.a exists"
        install_fido_zlib_pc
        return 0
    fi

    prepare_zlib_build_source

    local build_dir="${BUILD_CLIBS}/zlib-build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "[BUILD] zlib..."
    (
        cd "$build_dir"
        cmake "$ZLIB_BUILD_SOURCE" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DCMAKE_INSTALL_PREFIX="$FIDO_PREFIX" \
            -DCMAKE_INSTALL_LIBDIR=lib
        cmake --build . --parallel "$JOBS"
        cmake --install .
    )
    normalize_fido_libdir
    install_fido_zlib_pc
}

build_openssl() {
    local out="${FIDO_PREFIX}/lib/libcrypto.a"
    if [ -f "$out" ]; then
        echo "[OK] libcrypto.a exists"
        write_fido_libcrypto_pc "$FIDO_PREFIX" "$OPENSSL_VERSION"
        return 0
    fi

    clone_tag "https://github.com/openssl/openssl.git" "$OPENSSL_SRC" "openssl-${OPENSSL_VERSION}" "$OPENSSL_COMMIT"

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
    # Recover archives left in lib64 from earlier RHEL/Alma cmake installs.
    if [ ! -f "$out" ]; then
        normalize_fido_libdir
    fi
    if [ -f "$out" ]; then
        echo "[OK] libcbor.a exists"
        return 0
    fi

    clone_tag "https://github.com/PJK/libcbor.git" "$CBOR_SRC" "v${LIBCBOR_VERSION}" "$LIBCBOR_COMMIT"

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
            -DCMAKE_INSTALL_LIBDIR=lib \
            "${CMAKE_EXTRA_ARGS[@]}"
        cmake --build . --parallel "$JOBS"
        cmake --install .
    )
    normalize_fido_libdir
}

build_libfido2() {
    local out="${FIDO_PREFIX}/lib/libfido2.a"
    if [ ! -f "$out" ]; then
        normalize_fido_libdir
    fi
    if [ -f "$out" ]; then
        echo "[OK] libfido2.a exists"
        return 0
    fi

    clone_tag "https://github.com/Yubico/libfido2.git" "$FIDO_SRC" "${LIBFIDO2_VERSION}" "$LIBFIDO2_COMMIT"

    local build_dir="${BUILD_CLIBS}/libfido2-build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    echo "[BUILD] libfido2..."
    require_linux_udev_dev
    normalize_fido_libdir
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
            -DBUILD_TESTS=OFF \
            -DCMAKE_INSTALL_PREFIX="$FIDO_PREFIX" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCRYPTO_BACKEND=openssl \
            "${CMAKE_EXTRA_ARGS[@]}"
        cmake --build . --parallel "$JOBS"
        cmake --install .
    )
    normalize_fido_libdir
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
