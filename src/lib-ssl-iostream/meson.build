deps = [dep_lib, dep_settings, dep_var_expand, ext_ssl]

defines = [f'-DMODULE_DIR="@dovecot_moduledir@"']

# OpenSSL backend, compiled once and reused both by the shared module and by binaries that
# statically link the backend. PIC so that its objects can go into the shared module.
lib_ssl_iostream_openssl_static = static_library(
  'ssl-iostream-openssl-static',
  'dovecot-openssl-common.c',
  'iostream-openssl.c',
  'iostream-openssl-common.c',
  'iostream-openssl-context.c',
  'istream-openssl.c',
  'ostream-openssl.c',
  dependencies: deps,
  c_args: defines,
  pic: true,
)

# Loadable module. liblib/etc symbols are resolved from the loading binary during dlopen,
# so they must not be bundled in: reuse the backend objects and link only the external SSL
# libraries. Use extract_all_objects and don't link_whole so that the backend's
# dependencies aren't dragged in.
shared_module(
  'ssl_iostream_openssl',
  objects: lib_ssl_iostream_openssl_static.extract_all_objects(
    recursive: false,
  ),
  dependencies: [ext_ssl],
  install: true,
  install_dir: dovecot_moduledir,
)

install_headers(
  'iostream-openssl.h',
  'iostream-ssl.h',
  'iostream-ssl-private.h',
  'iostream-ssl-test.h',
  'ssl-settings.h',
  install_dir: dovecot_includedir,
)

dep_ssl_iostream_openssl_static = declare_dependency(
  link_with: lib_ssl_iostream_openssl_static,
  include_directories: include_directories('.'),
  dependencies: deps,
)

lib_ssl_iostream = static_library(
  'ssl-iostream',
  'iostream-ssl.c',
  'iostream-ssl-context-cache.c',
  'iostream-ssl-test.c',
  'ssl-settings.c',
  dependencies: deps,
  c_args: defines,
)

dep_ssl_iostream = declare_dependency(
  link_with: lib_ssl_iostream,
  include_directories: include_directories('.'),
  dependencies: deps,
)

test_deps = [deps, dep_test, dep_dns, dep_ssl_iostream_openssl_static, dep_ssl_iostream]

test(
  'iostream-ssl',
  executable(
    'test-iostream-ssl',
    'test-iostream-ssl.c',
    dependencies: test_deps,
  ),
  suite: 'ssl-iostream',
)
