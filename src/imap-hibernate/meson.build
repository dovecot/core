executable(
  'imap-hibernate',
  'imap-client.c',
  'imap-hibernate-client.c',
  'imap-hibernate-settings.c',
  'imap-master-connection.c',
  'main.c',
  extra_files: [
    'imap-client.h',
    'imap-hibernate-client.h',
    'imap-master-connection.h',
  ],
  dependencies: dep_dovecot,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)
