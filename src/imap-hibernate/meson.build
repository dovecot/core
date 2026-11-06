imap_hibernate = executable(
  'imap-hibernate',
  'imap-client.c',
  'imap-client-input.c',
  'imap-hibernate-client.c',
  'imap-hibernate-settings.c',
  'imap-master-connection.c',
  'main.c',
  extra_files: [
    'imap-client.h',
    'imap-client-input.h',
    'imap-hibernate-client.h',
    'imap-master-connection.h',
  ],
  dependencies: dep_dovecot,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)

test(
  'client-input',
  executable(
    'test-imap-client-input',
    'test-imap-client-input.c',
    objects: imap_hibernate.extract_objects('imap-client-input.c'),
    dependencies: [dep_test, dep_imap, dep_lib],
  ),
  suite: 'imap-hibernate',
)
