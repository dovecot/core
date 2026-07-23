deps = [
  dep_lib,
  dep_test,
  dep_auth_client,
  dep_master,
  dep_sasl,
]

lib_login = static_library(
  'login',
  'login-client.c',
  'login-server.c',
  'login-server-auth.c',
  dependencies: deps,
)

dep_login = declare_dependency(
  link_with: lib_login,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'login-client.h',
  'login-interface.h',
  'login-server.h',
  'login-server-auth.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  deps,
  dep_login,
  dep_dns_client,
  dep_dns,
  dep_ssl_iostream,
  dep_settings,
  dep_var_expand,
]

test(
  'server-auth',
  executable(
    'test-login-server-auth',
    'test-login-server-auth.c',
    dependencies: test_deps,
    export_dynamic: true,
  ),
  suite: 'login',
)
