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
BIN="scx_flow"
VER="5.3.3"
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
# an absolute path without whitespace or glob characters.
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
# directory that would really be removed: /tmp/scx-foo/../other is
# checked as /tmp/other, and a link is checked as its target.
canon() {
    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$1"
    elif command -v readlink >/dev/null 2>&1; then
        readlink -m "$1"
    else
        return 1
    fi
}
WS="$(canon "${WS}")" || {
    echo "refusing without canonical tool" >&2
    exit 1
}
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
# Only scratch places are cleaned: a /tmp/scx-* directory, the workspace in
# the cache directory of the user, or a directory that this script set up
# before and marked as its workspace. Anything else could hold data that
# is not ours.
MARKER=".scx_flow_workspace"
CACHE_WS=""
if [ -n "${XDG_CACHE_HOME:-}" ] || [ -n "${HOME:-}" ]; then
    CACHE_WS="$(canon "${XDG_CACHE_HOME:-${HOME}/.cache}/scx-flow-ws")"
fi
allowed=0
case "${WS}" in
    /tmp/scx-?*) allowed=1 ;;
esac
if [ -n "${CACHE_WS}" ] && [ "${WS}" = "${CACHE_WS}" ]; then
    allowed=1
fi
if [ -d "${WS}" ] && [ -f "${WS}/${MARKER}" ] && [ ! -L "${WS}/${MARKER}" ]; then
    allowed=1
fi
if [ "${allowed}" != "1" ]; then
    echo "refusing to clean ${WS}: use /tmp/scx-*${CACHE_WS:+ or ${CACHE_WS}}" >&2
    exit 1
fi
DEST="${WS}/scheds/experimental/scx_flow"

# Fail before the slow part when the result could not be used or installed.
if [ ! -d /sys/kernel/sched_ext ]; then
    echo "this kernel has no sched_ext (/sys/kernel/sched_ext is missing)" >&2
    exit 1
fi
if [ ! -w /usr/local/bin ]; then
    echo "cannot write to /usr/local/bin, run the installer as root" >&2
    exit 1
fi
# Check once more right before removing, in case the path was swapped
# for a symlink in the meantime.
if [ -L "${WS}" ]; then
    echo "refusing a symlinked workspace path" >&2
    exit 1
fi
echo "cleaning workspace at ${WS} for a fresh rebuild"
rm -rf -- "${WS}"
mkdir -p -- "${WS}"
: > "${WS}/${MARKER}"

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
if ! install -m 0755 "${WS}/target/release/${BIN}" "/usr/local/bin/${BIN}"; then
    echo "failed to install /usr/local/bin/${BIN}" >&2
    exit 1
fi

# Set CLEAN=1 to remove the build directory of the workspace once the
# binary is installed. The next run then builds everything from scratch.
if [ "${CLEAN:-0}" = "1" ]; then
    echo "cleaning workspace target to save space"
    rm -rf -- "${WS}/target"
fi

echo "done"
