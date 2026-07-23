#!/bin/sh

set -eu

# serial 1

: "${MESON_DIST_ROOT:?must be run as a meson dist script}"

# Origin directory.
src_dir="$1"
shift

# Destination directory.
dst_subdir="$1"
shift
dst_dir="${MESON_DIST_ROOT}/${dst_subdir}"
mkdir -p "${dst_dir}"

for ucd_filename; do
  src_filename="${src_dir}/${ucd_filename}"
  dst_filename="${dst_dir}/${ucd_filename}"

  if ! test -f "${src_filename}"; then
    echo "$0: ${src_filename} is missing, build the project first" >&2
    exit 1
  fi

  cp "${src_filename}" "${dst_filename}"
done
