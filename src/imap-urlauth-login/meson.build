executable(
  'imap-urlauth-login',
  'imap-urlauth-login.c',
  'imap-urlauth-login-settings.c',
  dependencies: dep_dovecot_login,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)
