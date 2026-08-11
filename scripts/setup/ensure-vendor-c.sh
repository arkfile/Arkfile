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

    if git -C "$dest" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        local current_commit target_commit
        current_commit=$(git -C "$dest" rev-parse HEAD)
        if [ "$ref_kind" = "tag" ]; then
            git -C "$dest" fetch --depth 1 origin "refs/tags/${ref}:refs/tags/${ref}" 2>/dev/null || true
            target_commit=$(git -C "$dest" rev-list -n 1 "$ref" 2>/dev/null || true)
        else
            git -C "$dest" fetch --depth 1 origin "$ref" 2>/dev/null || true
            target_commit="$ref"
        fi
        if [ -z "$target_commit" ] || ! git -C "$dest" cat-file -e "${target_commit}^{commit}" 2>/dev/null; then
            echo "[X] Unable to resolve pinned $ref_kind $ref for $dest" >&2
            return 1
        fi
        if [ "$dest" = "$LIBSODIUM_DIR" ] && [ "$target_commit" != "$VENDOR_C_LIBSODIUM_COMMIT" ]; then
            echo "[X] libsodium tag $ref resolved to $target_commit; expected $VENDOR_C_LIBSODIUM_COMMIT" >&2
            return 1
        fi
        if [ "$current_commit" != "$target_commit" ]; then
            if [ -n "$(git -C "$dest" status --porcelain 2>/dev/null)" ]; then
                echo "[X] Refusing to replace modified vendored source: $dest" >&2
                echo "    Expected: $target_commit" >&2
                echo "    Current:  $current_commit" >&2
                return 1
            fi
            echo "[INFO] Updating existing clone: $dest ($ref_kind $ref)"
            git -C "$dest" checkout --detach "$target_commit"
        fi
        if [ "$dest" = "$VENDOR_C_LIBOPAQUE_DIR" ]; then
            if ! git -C "$dest" diff --quiet HEAD -- src ':(exclude)src/oprf/**'; then
                echo "[X] Pinned libopaque C source has local modifications: $dest/src" >&2
                return 1
            fi
        elif [ "$dest" = "$VENDOR_C_LIBOPRF_DIR" ]; then
            if ! git -C "$dest" diff --quiet HEAD -- src; then
                echo "[X] Pinned liboprf source has local modifications: $dest/src" >&2
                return 1
            fi
        elif ! git -C "$dest" diff --quiet HEAD -- .; then
            echo "[X] Pinned vendored source has local tracked modifications: $dest" >&2
            return 1
        fi
        echo "[OK] Verified vendored source pin: $dest ($target_commit)"
        return 0
    fi
    if [ -e "$dest" ]; then
        echo "[X] Existing vendored source is not a verifiable Git checkout: $dest" >&2
        return 1
    fi

    echo "[INFO] Cloning $url into $dest ($ref_kind $ref)"
    if [ "$ref_kind" = "tag" ]; then
        git clone --depth 1 --branch "$ref" "$url" "$dest"
    else
        git clone "$url" "$dest"
        git -C "$dest" checkout -f "$ref"
    fi
    local cloned_commit
    cloned_commit=$(git -C "$dest" rev-parse HEAD)
    if [ "$ref_kind" = "commit" ] && [ "$cloned_commit" != "$ref" ]; then
        echo "[X] Cloned source is $cloned_commit; expected $ref" >&2
        return 1
    fi
    if [ "$dest" = "$LIBSODIUM_DIR" ] && [ "$cloned_commit" != "$VENDOR_C_LIBSODIUM_COMMIT" ]; then
        echo "[X] Cloned libsodium tag is $cloned_commit; expected $VENDOR_C_LIBSODIUM_COMMIT" >&2
        return 1
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

    if ! command -v git >/dev/null 2>&1; then
        echo "[X] git is required to verify vendored C sources"
        print_native_build_deps_hint
        return 1
    fi

    if ! vendor_c_sources_present; then
        echo "[INFO] C vendor sources missing; initializing under $VENDOR_C_ROOT..."
        try_git_submodules || true
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
