deps = [dep_lib, ext_iconv]

lib_charset = static_library(
  'charset',
  'charset-iconv.c',
  'charset-utf8.c',
  dependencies: deps,
)

dep_charset = declare_dependency(
  link_with: lib_charset,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'charset-utf8.h',
  'charset-utf8-private.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_test, dep_charset]

test(
  'charset',
  executable(
    'test-charset',
    'test-charset.c',
    dependencies: test_deps,
  ),
  suite: 'charset',
)
