#!/bin/sh

set -eu

# serial 1

# Release tarball files like version.txt and dovecot-version.h are written here.

version="$1"
srcdir="$2"

: "${MESON_DIST_ROOT:?must be run as a meson dist script}"

echo "${version}" > "${MESON_DIST_ROOT}/version.txt"

# This runs in the source tree where .git still exists and records the revision the
# tarball was taken from.
sh "${srcdir}/update-version.sh" "${srcdir}" "${MESON_DIST_ROOT}"
