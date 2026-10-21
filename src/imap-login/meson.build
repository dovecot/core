headers = [
  'imap-login-client.h',
  'imap-login-commands.h',
  'imap-login-settings.h',
]

executable(
  'imap-login',
  'imap-login-client.c',
  'client-authenticate.c',
  'imap-login-cmd-id.c',
  'imap-login-commands.c',
  'imap-login-settings.c',
  'imap-proxy.c',
  extra_files: [headers, 'client-authenticate.h', 'imap-proxy.h'],
  dependencies: [dep_compression, dep_dovecot_login],
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)

install_headers(headers, install_dir: dovecot_includedir)
