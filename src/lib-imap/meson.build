deps = [
  dep_lib,
  dep_charset,
  dep_mail,
]

lib_imap = static_library(
  'imap',
  'imap-arg.c',
  'imap-base-subject.c',
  'imap-bodystructure.c',
  'imap-date.c',
  'imap-envelope.c',
  'imap-id.c',
  'imap-keepalive.c',
  'imap-match.c',
  'imap-parser.c',
  'imap-quote.c',
  'imap-seqset.c',
  'imap-url.c',
  'imap-utf7.c',
  'imap-util.c',
  dependencies: deps,
)

dep_imap = declare_dependency(
  link_with: lib_imap,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'imap-arg.h',
  'imap-base-subject.h',
  'imap-bodystructure.h',
  'imap-date.h',
  'imap-envelope.h',
  'imap-id.h',
  'imap-keepalive.h',
  'imap-match.h',
  'imap-parser.h',
  'imap-quote.h',
  'imap-resp-code.h',
  'imap-seqset.h',
  'imap-stats.h',
  'imap-url.h',
  'imap-utf7.h',
  'imap-util.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  deps,
  dep_test,
  dep_imap,
]

tests = [
  'imap-bodystructure',
  'imap-date',
  'imap-envelope',
  'imap-match',
  'imap-parser',
  'imap-quote',
  'imap-seqset',
  'imap-url',
  'imap-utf7',
  'imap-util',
]

foreach test_name : tests
  exe = f'test-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'imap',
  )
endforeach

if get_option('fuzzing')
  fuzzers = [
    'imap-bodystructure',
    'imap-utf7',
    'imap-parser',
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
        suite: 'imap',
        timeout: fuzzer_test_timeout,
        workdir: meson.current_build_dir(),
      )
    endif
  endforeach
endif
