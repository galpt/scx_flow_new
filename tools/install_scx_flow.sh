#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
#
# Install the flow scheduler by overlaying the scx dir into
# a workspace checkout and building the binary.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_DIR}/scx"
WS="${1:-/tmp/opencode/scx}"
DEST="${WS}/scheds/experimental/scx_flow"
BIN="scx_flow"
VER="4.1.0"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool: $1" >&2
        exit 1
    }
}

need cargo
need clang
need rsync

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
rsync -a --delete "${SRC_DIR}/" "${DEST}/"

echo "building ${BIN} in workspace"
cargo build --manifest-path "${DEST}/Cargo.toml" --release

echo "installing binary"
install -m 0755 "${WS}/target/release/${BIN}" \
    "/usr/local/bin/${BIN}" 2>/dev/null || {
    echo "copying binary to current dir"
    cp "${WS}/target/release/${BIN}" "${REPO_DIR}/${BIN}"
}

echo "done"
