executable(
  'pop3-login',
  'client.c',
  'client-authenticate.c',
  'pop3-login-settings.c',
  'pop3-proxy.c',
  extra_files: [
    'client.h',
    'client-authenticate.h',
    'pop3-proxy.h',
  ],
  dependencies: [dep_dovecot_login, dep_pop3],
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)
