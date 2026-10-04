#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Install the flow scheduler by overlaying the scx dir into
# a workspace checkout and building the binary.
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_DIR}/scx"
WS="${1:-/tmp/scx-workspace}"
DEST="${WS}/scheds/experimental/scx_flow"
BIN="scx_flow"
VER="4.7.6"
# Pinned upstream ref, same as repo CI.
SCX_REF="6752d59a4297d8918e8fd4d7237b50e2fceb1d14"
UPSTREAM="https://github.com/sched-ext/scx"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool: $1" >&2
        exit 1
    }
}

need cargo
need clang
need rsync
need git

# Always start from a fresh workspace so no run reuses
# an existing tree. Guard the remove against empty or root plus
# whitespace plus glob plus relative paths, so only an absolute
# workspace path without spaces is cleaned.
if [ -z "${WS}" ] || [ "${WS}" = "/" ] || [ "${WS}" = "//" ]; then
    echo "refusing to clean an empty or root path" >&2
    exit 1
fi
case "${WS}" in
    /*) ;;
    *)
        echo "refusing a non absolute workspace path" >&2
        exit 1
        ;;
esac
case "${WS}" in
    *' '* | *'*'* | *'?'* | *'['*)
        echo "refusing a workspace path with whitespace or glob" >&2
        exit 1
        ;;
esac
TAB=$'\t'
NL=$'\n'
case "${WS}" in
    *"${TAB}"* | *"${NL}"*)
        echo "refusing a workspace path with whitespace" >&2
        exit 1
        ;;
esac
# Canonicalize for symlink plus dotdot safety with no require-existing,
# so /tmp/scx-foo/../opencode still refuses as /tmp/opencode.
if command -v realpath >/dev/null 2>&1; then
    WS="$(realpath -m "${WS}")"
elif command -v readlink >/dev/null 2>&1; then
    WS="$(readlink -m "${WS}")"
else
    echo "refusing without canonical tool" >&2
    exit 1
fi
DEST="${WS}/scheds/experimental/scx_flow"
# Never clean the shared CI tree at /tmp/opencode, so local runs keep
# the pinned workspace plus caches intact with no accidental remove.
case "${WS}" in
    /tmp/opencode | /tmp/opencode/*)
        echo "refusing to clean /tmp/opencode" >&2
        exit 1
        ;;
esac
# Never clean the bare /tmp dir, so only allowlisted workspaces may
# live under /tmp with no accidental remove.
if [ "${WS}" = "/tmp" ]; then
    echo "refusing to clean /tmp" >&2
    exit 1
fi
# Allowlist /tmp/scx-* workspaces only under /tmp, so stray /tmp trees
# never clean with no accidental remove.
case "${WS}" in
    /tmp/*)
        case "${WS}" in
            /tmp/scx-*) ;;
            *)
                echo "refusing to clean non allowlisted /tmp path" >&2
                exit 1
                ;;
        esac
        ;;
esac
# Never clean home plus system trees, so user data plus OS stays intact.
if [ -n "${HOME:-}" ]; then
    if [ "${WS}" = "${HOME}" ]; then
        echo "refusing to clean HOME" >&2
        exit 1
    fi
    case "${WS}" in
        "${HOME}"/*)
            echo "refusing to clean HOME tree" >&2
            exit 1
            ;;
    esac
fi
case "${WS}" in
    /home | /home/*)
        echo "refusing to clean /home" >&2
        exit 1
        ;;
    /usr | /usr/*)
        echo "refusing to clean /usr" >&2
        exit 1
        ;;
    /var | /var/*)
        echo "refusing to clean /var" >&2
        exit 1
        ;;
esac
echo "cleaning workspace at ${WS} for a fresh rebuild"
rm -rf "${WS}"
mkdir -p "${WS}"
# Fetch the pinned upstream ref by SHA and checkout the result.
git init -q "${WS}"
git -C "${WS}" remote add origin "${UPSTREAM}"
if ! git -C "${WS}" fetch origin "${SCX_REF}"; then
    echo "fetch failed, check network access to ${UPSTREAM}" >&2
    exit 1
fi
git -C "${WS}" checkout FETCH_HEAD

if [ ! -d "${WS}/rust" ]; then
    echo "workspace rust dir not found at ${WS}/rust" >&2
    exit 1
fi

if [ ! -d "${SRC_DIR}/src" ]; then
    echo "source dir not found at ${SRC_DIR}/src" >&2
    exit 1
fi

got="$(grep '^version' "${SRC_DIR}/Cargo.toml" | head -n 1 | cut -d '"' -f 2)"
if [ "${got}" != "${VER}" ]; then
    echo "version mismatch: got ${got} want ${VER}" >&2
    exit 1
fi

echo "overlaying ${SRC_DIR} to ${DEST}"
mkdir -p "${DEST}"
rsync -a --delete --exclude /target/ "${SRC_DIR}/" "${DEST}/"

echo "building ${BIN} in workspace"
cargo build --manifest-path "${DEST}/Cargo.toml" --release

echo "installing binary"
install -m 0755 "${WS}/target/release/${BIN}" \
    "/usr/local/bin/${BIN}" 2>/dev/null || {
    echo "copying binary to current dir"
    cp "${WS}/target/release/${BIN}" "${REPO_DIR}/${BIN}"
}

# Opt in workspace clean only after install wins.
# Set CLEAN to 1 to remove the workspace target dir
# after a good install. Never runs on failure since
# the script exits early on any fault. Rebuild after
# a clean fetches plus builds from scratch and takes
# a while on first run with a fresh download.
if [ "${CLEAN:-0}" = "1" ]; then
    echo "cleaning workspace target to save space"
    rm -rf "${WS}/target"
fi

echo "done"
