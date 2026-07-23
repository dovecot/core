deps = [dep_lib, dep_settings, dep_json, dep_var_expand, dep_dcrypt, dep_dict, dep_http]

lib_oauth2 = static_library(
  'oauth2',
  'oauth2.c',
  'oauth2-request.c',
  'oauth2-jwt.c',
  'oauth2-key-cache.c',
  dependencies: deps,
)

dep_oauth2 = declare_dependency(
  link_with: lib_oauth2,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'oauth2.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  deps,
  dep_test,
  dep_oauth2,
  dep_dcrypt_openssl_static,
  dep_ssl_iostream_openssl_static,
]
tests = ['json', 'jwt']

foreach test_name : tests
  exe = f'test-oauth2-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'oauth2',
  )
endforeach
