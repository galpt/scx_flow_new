#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Build and install scx_flow by copying the scx directory into a checkout
# of the scx workspace.
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_DIR}/scx"
WS="${1:-/tmp/scx-workspace}"
DEST="${WS}/scheds/experimental/scx_flow"
BIN="scx_flow"
VER="5.2.26"
# The workspace commit is pinned and matches the one CI uses. CI fetches
# it from sched-ext/scx, the installer from the galpt/scx mirror, and the
# check after the fetch refuses any other commit.
SCX_REF="e7b3a219617472cf78880ac424714e52c932db61"
FORK="https://github.com/galpt/scx"

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

# The scheduler relies on kfuncs and compat helpers that need 7.1 or later.
krel="$(uname -r)"
kmaj="$(printf '%s' "${krel}" | cut -d . -f 1 | tr -cd '0-9')"
kmin="$(printf '%s' "${krel}" | cut -d . -f 2 | tr -cd '0-9')"
if [ -z "${kmaj}" ] || [ -z "${kmin}" ]; then
    echo "refusing without a parsable kernel version from ${krel}" >&2
    exit 1
fi
if [ "${kmaj}" -lt 7 ] || { [ "${kmaj}" -eq 7 ] && [ "${kmin}" -lt 1 ]; }; then
    echo "refusing kernel ${krel}: need 7.1 or later" >&2
    exit 1
fi

# The workspace is removed and fetched again on every run, so only accept
# an absolute path without whitespace or glob characters, and refuse
# anything that could point at data outside of a scratch directory.
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
# Resolve symlinks, "." and "..", so the checks below apply to the
# directory that would really be removed: /tmp/scx-foo/../opencode is
# checked as /tmp/opencode, and a link is checked as its target.
if command -v realpath >/dev/null 2>&1; then
    WS="$(realpath -m "${WS}")"
elif command -v readlink >/dev/null 2>&1; then
    WS="$(readlink -m "${WS}")"
else
    echo "refusing without canonical tool" >&2
    exit 1
fi
# The path is resolved now, so a symlink here or in a parent directory
# means it was swapped after the check.
if [ -L "${WS}" ]; then
    echo "refusing a symlinked workspace path" >&2
    exit 1
fi
_parent="${WS}"
while [ "${_parent}" != "/" ] && [ "${_parent}" != "." ] && [ -n "${_parent}" ]; do
    if [ -L "${_parent}" ]; then
        echo "refusing a symlinked parent path" >&2
        exit 1
    fi
    _parent="$(dirname "${_parent}")"
done
DEST="${WS}/scheds/experimental/scx_flow"
# /tmp/opencode holds the workspace and caches CI uses.
case "${WS}" in
    /tmp/opencode | /tmp/opencode/*)
        echo "refusing to clean /tmp/opencode" >&2
        exit 1
        ;;
esac
if [ "${WS}" = "/tmp" ]; then
    echo "refusing to clean /tmp" >&2
    exit 1
fi
# Under /tmp, only directories named scx-* are used.
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
# Check once more right before removing, in case the path was swapped
# for a symlink in the meantime.
if [ -L "${WS}" ]; then
    echo "refusing a symlinked workspace path" >&2
    exit 1
fi
case "${WS}" in
    /tmp/opencode | /tmp/opencode/*)
        echo "refusing to clean /tmp/opencode" >&2
        exit 1
        ;;
esac
echo "cleaning workspace at ${WS} for a fresh rebuild"
rm -rf -- "${WS}"
mkdir -p -- "${WS}"

git init -q "${WS}"
git -C "${WS}" remote add origin "${FORK}"
if ! git -C "${WS}" fetch origin "${SCX_REF}"; then
    echo "fetch failed, check network access to ${FORK}" >&2
    exit 1
fi
got_ref="$(git -C "${WS}" rev-parse FETCH_HEAD)"
if [ "${got_ref}" != "${SCX_REF}" ]; then
    echo "ref mismatch: got ${got_ref} want ${SCX_REF}" >&2
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

# The license is the one of the workspace.
if [ "$(readlink "${DEST}/LICENSE" 2>/dev/null)" != "../../../LICENSE" ]; then
    rm -f -- "${DEST}/LICENSE"
    ln -s ../../../LICENSE "${DEST}/LICENSE"
fi

echo "building ${BIN} in workspace"
cargo build --manifest-path "${DEST}/Cargo.toml" --release

echo "installing binary"
install -m 0755 "${WS}/target/release/${BIN}" \
    "/usr/local/bin/${BIN}" 2>/dev/null || {
    echo "copying binary to current dir"
    cp "${WS}/target/release/${BIN}" "${REPO_DIR}/${BIN}"
}

# Set CLEAN=1 to remove the build directory of the workspace once the
# binary is installed. The next run then builds everything from scratch.
if [ "${CLEAN:-0}" = "1" ]; then
    echo "cleaning workspace target to save space"
    rm -rf -- "${WS}/target"
fi

echo "done"
