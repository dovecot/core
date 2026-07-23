deps = [dep_lib]

lib_dns = static_library(
  'dns',
  'dns-util.c',
  dependencies: deps,
)

dep_dns = declare_dependency(
  link_with: lib_dns,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'dns-util.h',
  install_dir: dovecot_includedir,
)

test(
  'dns-util',
  executable(
    'test-dns-util',
    'test-dns-util.c',
    dependencies: [
      dep_lib,
      dep_test,
      dep_dns,
    ],
  ),
  suite: 'dns',
)
