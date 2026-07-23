# TODO: Deliberately without a consumer until src/pop3 and src/pop3-login are ported.
dep_pop3 = declare_dependency(
  include_directories: include_directories('.'),
)

install_headers(
  'pop3-capability.h',
  'pop3-protocol.h',
  install_dir: dovecot_includedir,
)
