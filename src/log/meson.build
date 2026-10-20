executable(
  'log',
  'doveadm-connection.c',
  'log-connection.c',
  'log-settings.c',
  'main.c',
  extra_files: [
    'doveadm-connection.h',
    'log-connection.h',
  ],
  dependencies: dep_dovecot,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)
