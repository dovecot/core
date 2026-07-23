deps = [dep_lib]

lib_auth = static_library(
  'auth',
  'auth-digest.c',
  'auth-gs2.c',
  'auth-scram.c',
  'auth-scram-client.c',
  'auth-scram-server.c',
  'crypt-blowfish.c',
  'password-scheme.c',
  'password-scheme-md5crypt.c',
  'password-scheme-scram.c',
  'password-scheme-pbkdf2.c',
  dependencies: deps,
)

dep_auth = declare_dependency(
  link_with: lib_auth,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'mycrypt.h',
  'auth-digest.h',
  'auth-gs2.h',
  'auth-gssapi.h',
  'auth-scram.h',
  'auth-scram-client.h',
  'auth-scram-server.h',
  'password-scheme.h',
  install_dir: dovecot_includedir,
)

auth_crypt_deps = [deps, ext_sodium, ext_crypt]

lib_auth_crypt = static_library(
  'auth-crypt',
  'mycrypt.c',
  'password-scheme-crypt.c',
  'password-scheme-sodium.c',
  dependencies: auth_crypt_deps,
)

dep_auth_crypt = declare_dependency(
  link_with: lib_auth_crypt,
  include_directories: include_directories('.'),
  dependencies: auth_crypt_deps,
)

if have_gssapi
  auth_gssapi_deps = [deps, ext_gssapi]

  dep_auth_gssapi = declare_dependency(
    link_with: static_library(
      'auth-gssapi',
      'auth-gssapi.c',
      dependencies: auth_gssapi_deps,
    ),
    include_directories: include_directories('.'),
    dependencies: auth_gssapi_deps,
  )
endif

tests = ['password-scheme', 'auth-scram', 'auth-gs2']

foreach test_name : tests
  exe = f'test-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: [
        deps,
        dep_test,
        dep_auth,
        dep_auth_crypt,
        ext_sodium,
      ],
      export_dynamic: true,
    ),
    suite: 'auth',
  )
endforeach
