headers = [
  'imapc-client.h',
  'imapc-client-private.h',
  'imapc-client-settings.h',
  'imapc-connection.h',
  'imapc-msgmap.h',
]

lib_imap_client = static_library(
  'imap-client',
  'imapc-client-settings.c',
  'imapc-client.c',
  'imapc-connection.c',
  'imapc-msgmap.c',
  extra_files: headers,
  dependencies: dep_dovecot,
)

dep_imap_client = declare_dependency(
  link_with: lib_imap_client,
  include_directories: include_directories('.'),
)

install_headers(headers, install_dir: dovecot_includedir)

test(
  'imapc-client',
  executable(
    'test-imapc-client',
    'test-imapc-client.c',
    dependencies: [dep_test, dep_imap_client, dep_dovecot],
  ),
  suite: 'imap-client',
)
