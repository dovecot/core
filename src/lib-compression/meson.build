headers = [
  'compression.h',
  'iostream-lz4.h',
  'istream-zlib.h',
  'ostream-zlib.h',
]

deps = [ext_zlib, ext_bzlib, ext_lz4, ext_zstd]

lib_compression = static_library(
  'compression',
  'compression.c',
  'istream-decompress.c',
  'istream-lz4.c',
  'istream-zlib.c',
  'istream-bzlib.c',
  'istream-zstd.c',
  'ostream-lz4.c',
  'ostream-zlib.c',
  'ostream-bzlib.c',
  'ostream-zstd.c',
  extra_files: [headers, 'iostream-zstd-private.h'],
  dependencies: [deps, dep_dovecot],
)

dep_compression = declare_dependency(
  link_with: lib_compression,
  include_directories: include_directories('.'),
  dependencies: deps,
)

shared_library(
  'dovecot-compression',
  link_whole: lib_compression,
  dependencies: [deps, dep_dovecot],
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: dovecot_pkglibdir,
  version: '0.0.0',
)

install_headers(headers, install_dir: dovecot_includedir)

test_deps = [dep_test, dep_compression, dep_dovecot]

test(
  'compression',
  executable(
    'test-compression',
    'test-compression.c',
    dependencies: test_deps,
  ),
  suite: 'compression',
)

executable(
  'bench-compression',
  'bench-compression.c',
  dependencies: test_deps,
)
