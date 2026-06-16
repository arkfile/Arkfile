#!/bin/bash
# Ensure vendored C/crypto sources exist under vendor_c/ (separate from Go vendor/).
# go mod vendor owns ./vendor/ only; this script must run before any C library build.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build-config.sh
source "$SCRIPT_DIR/build-config.sh"

clone_pinned_repo() {
    local url="$1"
    local dest="$2"
    local ref="$3"
    local ref_kind="${4:-commit}"

    if [ -z "$url" ] || [ -z "$dest" ] || [ -z "$ref" ]; then
        echo "[X] clone_pinned_repo: missing arguments" >&2
        return 1
    fi

    mkdir -p "$(dirname "$dest")"

    if [ -d "$dest/.git" ]; then
        echo "[INFO] Updating existing clone: $dest ($ref_kind $ref)"
        git -C "$dest" fetch --depth 1 origin "$ref" 2>/dev/null || git -C "$dest" fetch --depth 1 origin 2>/dev/null || true
        if [ "$ref_kind" = "tag" ]; then
            git -C "$dest" checkout -f "$ref"
        else
            git -C "$dest" checkout -f "$ref"
        fi
        return 0
    fi

    echo "[INFO] Cloning $url into $dest ($ref_kind $ref)"
    if [ "$ref_kind" = "tag" ]; then
        git clone --depth 1 --branch "$ref" "$url" "$dest"
    else
        git clone "$url" "$dest"
        git -C "$dest" checkout -f "$ref"
    fi
}

migrate_legacy_vendor_paths() {
    if [ ! -d "vendor/stef" ] && [ ! -d "vendor/jedisct1" ]; then
        return 0
    fi

    echo "[INFO] Migrating legacy C trees from vendor/ to vendor_c/..."

    if [ -d "vendor/stef/libopaque" ] && [ ! -d "$VENDOR_C_LIBOPAQUE_DIR" ]; then
        mkdir -p "$VENDOR_C_STEF"
        mv "vendor/stef/libopaque" "$VENDOR_C_LIBOPAQUE_DIR"
    fi
    if [ -d "vendor/stef/liboprf" ] && [ ! -d "$VENDOR_C_LIBOPRF_DIR" ]; then
        mkdir -p "$VENDOR_C_STEF"
        mv "vendor/stef/liboprf" "$VENDOR_C_LIBOPRF_DIR"
    fi
    if [ -d "vendor/jedisct1/libsodium" ] && [ ! -d "$LIBSODIUM_DIR" ]; then
        mkdir -p "$VENDOR_C_ROOT/jedisct1"
        mv "vendor/jedisct1/libsodium" "$LIBSODIUM_DIR"
    fi

    rmdir vendor/stef 2>/dev/null || true
    rmdir vendor/jedisct1 2>/dev/null || true
}

try_git_submodules() {
    if ! command -v git >/dev/null 2>&1; then
        return 1
    fi
    if [ ! -f .gitmodules ]; then
        return 1
    fi

    git submodule sync --recursive 2>/dev/null || true
    if git submodule update --init --recursive --force \
        "$VENDOR_C_LIBOPAQUE_DIR" \
        "$VENDOR_C_LIBOPRF_DIR" \
        "$LIBSODIUM_DIR" 2>/dev/null; then
        return 0
    fi
    if git submodule update --init --recursive --force 2>/dev/null; then
        return 0
    fi
    return 1
}

vendor_c_sources_present() {
    [ -f "$OPAQUE_C_SOURCE" ] && \
    [ -f "$OPRF_C_SOURCE" ] && \
    { [ -f "$LIBSODIUM_DIR/configure" ] || [ -f "$LIBSODIUM_DIR/autogen.sh" ]; }
}

ensure_vendor_c_sources() {
    migrate_legacy_vendor_paths

    if vendor_c_sources_present; then
        echo "[OK] C vendor sources present under $VENDOR_C_ROOT"
        return 0
    fi

    echo "[INFO] C vendor sources missing; initializing under $VENDOR_C_ROOT..."

    try_git_submodules || true

    if ! vendor_c_sources_present; then
        if ! command -v git >/dev/null 2>&1; then
            echo "[X] git is required to fetch vendored C sources"
            print_native_build_deps_hint
            return 1
        fi

        clone_pinned_repo \
            "https://github.com/stef/libopaque.git" \
            "$VENDOR_C_LIBOPAQUE_DIR" \
            "$VENDOR_C_LIBOPAQUE_COMMIT" \
            commit

        clone_pinned_repo \
            "https://github.com/stef/liboprf.git" \
            "$VENDOR_C_LIBOPRF_DIR" \
            "$VENDOR_C_LIBOPRF_COMMIT" \
            commit

        clone_pinned_repo \
            "https://github.com/jedisct1/libsodium.git" \
            "$LIBSODIUM_DIR" \
            "$VENDOR_C_LIBSODIUM_TAG" \
            tag
    fi

    if ! vendor_c_sources_present; then
        echo "[X] Failed to provision C vendor sources under $VENDOR_C_ROOT"
        echo "    Expected:"
        echo "      $OPAQUE_C_SOURCE"
        echo "      $OPRF_C_SOURCE"
        echo "      $LIBSODIUM_DIR/configure (or autogen.sh)"
        return 1
    fi

    echo "[OK] C vendor sources ready under $VENDOR_C_ROOT"
    return 0
}

ensure_vendor_c_sources
