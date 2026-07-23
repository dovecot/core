deps = [dep_lib, dep_test, dep_settings, dep_master, dep_var_expand, dep_sasl]

lib_auth_client = static_library(
  'auth-client',
  'auth-client.c',
  'auth-client-request.c',
  'auth-client-connection.c',
  'auth-master.c',
  'auth-master-request.c',
  'auth-proxy.c',
  dependencies: deps,
)

dep_auth_client = declare_dependency(
  link_with: lib_auth_client,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'auth-sasl-common.h',
  'auth-client.h',
  'auth-client-interface.h',
  'auth-client-private.h',
  'auth-master.h',
  'auth-master-private.h',
  'auth-proxy.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_dns, dep_auth_client]

tests = ['client', 'master']

foreach test_name : tests
  exe = f'test-auth-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'auth-client',
  )
endforeach
