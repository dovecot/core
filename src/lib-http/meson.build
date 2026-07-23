deps = [
  dep_lib,
  dep_settings,
  dep_dns_client,
  dep_ssl_iostream,
  dep_master,
]

lib_http = static_library(
  'http',
  'http-auth.c',
  'http-client.c',
  'http-client-connection.c',
  'http-client-host.c',
  'http-client-peer.c',
  'http-client-queue.c',
  'http-client-request.c',
  'http-client-settings.c',
  'http-date.c',
  'http-header.c',
  'http-header-parser.c',
  'http-message-parser.c',
  'http-parser.c',
  'http-request.c',
  'http-request-parser.c',
  'http-response.c',
  'http-response-parser.c',
  'http-server.c',
  'http-server-connection.c',
  'http-server-ostream.c',
  'http-server-request.c',
  'http-server-resource.c',
  'http-server-response.c',
  'http-server-settings.c',
  'http-transfer-chunked.c',
  'http-url.c',
  dependencies: [deps, dir_defines],
)

dep_http = declare_dependency(
  link_with: lib_http,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'http-common.h',
  'http-date.h',
  'http-url.h',
  'http-parser.h',
  'http-header.h',
  'http-header-parser.h',
  'http-transfer.h',
  'http-auth.h',
  'http-message-parser.h',
  'http-request.h',
  'http-request-parser.h',
  'http-response.h',
  'http-response-parser.h',
  'http-client-private.h',
  'http-client.h',
  'http-server-private.h',
  'http-server.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  dep_http,
  dep_test,
  dep_lib,
  dep_settings,
  dep_dns_client,
  dep_ssl_iostream,
  dep_master,
  dep_ssl_iostream_openssl_static,
  dir_defines,
]

tests = [
  'auth',
  'client-errors',
  'client-request',
  'date',
  'header-parser',
  'payload',
  'request-parser',
  'response-parser',
  'server-errors',
  'transfer',
  'url',
]

executable(
  'test-http-server',
  'test-http-server.c',
  dependencies: test_deps,
)

executable(
  'test-http-client',
  'test-http-client.c',
  dependencies: test_deps,
)

foreach test_name : tests
  exe = f'test-http-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'http',
    timeout: 0,
    workdir: meson.current_source_dir(),
  )
endforeach

if get_option('fuzzing')
  fuzzers = [
    'http-request-parser',
    'http-response-parser',
  ]

  foreach fuzzer_name : fuzzers
    exe = f'fuzz-@fuzzer_name@'
    src = f'@exe@.c'
    fuzzer = executable(
      exe,
      src,
      link_language: 'cpp',
      pie: true,
      dependencies: [test_deps, ext_fuzzer],
    )

    if fuzzer_test_runs > 0
      test(
        exe,
        fuzzer,
        args: fuzzer_test_args,
        suite: 'http',
        timeout: fuzzer_test_timeout,
        workdir: meson.current_build_dir(),
      )
    endif
  endforeach
endif
