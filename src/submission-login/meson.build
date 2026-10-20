executable(
  'submission-login',
  'client.c',
  'client-authenticate.c',
  'submission-login-settings.c',
  'submission-proxy.c',
  extra_files: [
    'client.h',
    'client-authenticate.h',
    'submission-login-settings.h',
    'submission-proxy.h',
  ],
  dependencies: dep_dovecot_login,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)
