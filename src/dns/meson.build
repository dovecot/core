executable(
  'dns-client',
  'dns-client.c',
  'dns-client-settings.c',
  dependencies: dep_dovecot,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)
