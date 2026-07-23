deps = [
  dep_lib,
  dep_settings,
  dep_ssl_iostream,
  dep_mail,
  dep_sasl,
  dep_master,
  dep_dns_client,
  dep_program_client,
]

lib_smtp = static_library(
  'smtp',
  'smtp-address.c',
  'smtp-client.c',
  'smtp-client-command.c',
  'smtp-client-connection.c',
  'smtp-client-transaction.c',
  'smtp-command-parser.c',
  'smtp-common.c',
  'smtp-dovecot.c',
  'smtp-params.c',
  'smtp-parser.c',
  'smtp-reply.c',
  'smtp-reply-parser.c',
  'smtp-server.c',
  'smtp-server-cmd-auth.c',
  'smtp-server-cmd-data.c',
  'smtp-server-cmd-helo.c',
  'smtp-server-cmd-mail.c',
  'smtp-server-cmd-noop.c',
  'smtp-server-cmd-quit.c',
  'smtp-server-cmd-rcpt.c',
  'smtp-server-cmd-rset.c',
  'smtp-server-cmd-starttls.c',
  'smtp-server-cmd-vrfy.c',
  'smtp-server-cmd-xclient.c',
  'smtp-server-command.c',
  'smtp-server-connection.c',
  'smtp-server-recipient.c',
  'smtp-server-reply.c',
  'smtp-server-transaction.c',
  'smtp-submit.c',
  'smtp-submit-settings.c',
  'smtp-syntax.c',
  dependencies: deps,
)

dep_smtp = declare_dependency(
  link_with: lib_smtp,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'smtp-parser.h',
  'smtp-syntax.h',
  'smtp-address.h',
  'smtp-common.h',
  'smtp-params.h',
  'smtp-reply.h',
  'smtp-reply-parser.h',
  'smtp-command.h',
  'smtp-command-parser.h',
  'smtp-client-command.h',
  'smtp-client-transaction.h',
  'smtp-client-connection.h',
  'smtp-client-private.h',
  'smtp-client.h',
  'smtp-server-private.h',
  'smtp-server.h',
  'smtp-submit-settings.h',
  'smtp-submit.h',
  'smtp-dovecot.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  deps,
  dep_test,
  dep_smtp,
  dep_ssl_iostream_openssl_static,
  dep_auth,
]

tests = [
  'address',
  'client-errors',
  'command-parser',
  'params',
  'payload',
  'reply',
  'server-errors',
  'submit',
  'syntax',
]

current_source_dir = meson.current_source_dir()
test_defines = ['-DTEST_BIN_DIR="@0@"'.format(current_source_dir / 'test-bin')]

foreach test_name : tests
  exe = f'test-smtp-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
      c_args: test_defines,
    ),
    suite: 'smtp',
    timeout: 0,
    workdir: current_source_dir,
  )
endforeach

if get_option('fuzzing')
  fuzzer = executable(
    'fuzz-smtp-server',
    'fuzz-smtp-server.c',
    link_language: 'cpp',
    pie: true,
    dependencies: [test_deps, ext_fuzzer],
  )

  if fuzzer_test_runs > 0
    test(
      'fuzz-smtp-server',
      fuzzer,
      args: fuzzer_test_args,
      suite: 'smtp',
      timeout: fuzzer_test_timeout,
      workdir: meson.current_build_dir(),
    )
  endif
endif
