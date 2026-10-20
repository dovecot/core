headers = [
  'client-common.h',
  'login-common.h',
  'login-proxy.h',
  'login-proxy-state.h',
  'login-settings.h',
  'login-log.h',
  'sasl-proxy.h',
]

lib_login_common = static_library(
  'login-common',
  'client-common.c',
  'client-common-auth.c',
  'login-proxy.c',
  'login-proxy-state.c',
  'login-settings.c',
  'main.c',
  'sasl-proxy.c',
  extra_files: headers,
  dependencies: [dep_dovecot, dir_defines],
)

dlib_dovecot_login = shared_library(
  'dovecot-login',
  link_whole: lib_login_common,
  dependencies: dep_dovecot,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: dovecot_pkglibdir,
  version: '0.0.0',
)

dep_dovecot_login = declare_dependency(
  link_with: dlib_dovecot_login,
  include_directories: include_directories('.'),
  dependencies: dep_dovecot,
)

install_headers(headers, install_dir: dovecot_includedir)

test(
  'login-common',
  executable(
    'test-login-common',
    'test-login-common.c',
    link_with: lib_login_common,
    dependencies: [dep_test, dep_dovecot],
  ),
  suite: 'login-common',
)
