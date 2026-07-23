deps = [dep_lib, dep_json, dep_ssl_iostream]

lib_dcrypt = static_library(
  'dcrypt',
  'dcrypt.c',
  'istream-decrypt.c',
  'ostream-encrypt.c',
  dependencies: deps,
  c_args: f'-DDCRYPT_MODULE_DIR="@dovecot_moduledir@"',
)

dep_dcrypt = declare_dependency(
  link_with: lib_dcrypt,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'dcrypt.h',
  'dcrypt-iostream.h',
  'dcrypt-private.h',
  'ostream-encrypt.h',
  'istream-decrypt.h',
  install_dir: dovecot_includedir,
)

# OpenSSL backend, compiled once and reused both by the shared module and by binaries that
# statically link the backend. PIC so that its objects can go into the shared module.
dcrypt_openssl_deps = [dep_lib, ext_ssl, dep_json]

lib_dcrypt_openssl_static = static_library(
  'dcrypt-openssl-static',
  'dcrypt-openssl1.c',
  'dcrypt-openssl3.c',
  include_directories: ['../lib-ssl-iostream'],
  dependencies: dcrypt_openssl_deps,
  pic: true,
)

dep_dcrypt_openssl_static = declare_dependency(
  link_with: lib_dcrypt_openssl_static,
  include_directories: include_directories('.'),
  dependencies: dcrypt_openssl_deps,
)

# Loadable/shared module. Its liblib/libjson symbols are resolved from the loading binary
# during dlopen, so only the external SSL libraries are linked in here.  The backend needs
# dovecot_openssl_common_* (and, transitively, the OpenSSL error helper), so those two
# lib-ssl-iostream objects are bundled in here explicitly.
dlib_dcrypt_openssl = shared_module(
  'dcrypt_openssl',
  objects: [
    lib_dcrypt_openssl_static.extract_all_objects(
      recursive: false,
    ),
    lib_ssl_iostream_openssl_static.extract_objects(
      'dovecot-openssl-common.c',
      'iostream-openssl-common.c',
    ),
  ],
  dependencies: [ext_ssl],
  install: true,
  install_dir: dovecot_moduledir,
)

tests = ['crypto', 'stream']
test_deps = [deps, dep_test, dep_dcrypt]
test_defines = ['-DDCRYPT_SRC_DIR="@0@"'.format(meson.current_source_dir())]

foreach test_name : tests
  exe = f'test-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
      # Whole-archive liblib/libjson and export the dynamic symbols so the runtime-loaded
      # dcrypt_openssl module can resolve every lib/json symbol it needs from this binary.
      link_whole: [lib_lib, lib_json],
      export_dynamic: true,
      c_args: test_defines,
    ),
    suite: 'dcrypt',
    workdir: meson.current_build_dir(),
    depends: dlib_dcrypt_openssl,
  )
endforeach
