deps = [
  dep_lib,
  dep_settings,
  dep_charset,
]

lib_mail = static_library(
  'mail',
  'istream-attachment-connector.c',
  'istream-attachment-extractor.c',
  'istream-binary-converter.c',
  'istream-dot.c',
  'istream-header-filter.c',
  'istream-qp-decoder.c',
  'istream-qp-encoder.c',
  'mail-html2text.c',
  'mbox-from.c',
  'message-address.c',
  'message-binary-part.c',
  'message-date.c',
  'message-decoder.c',
  'message-header-decode.c',
  'message-header-encode.c',
  'message-header-hash.c',
  'message-header-parser.c',
  'message-id.c',
  'message-parser.c',
  'message-parser-from-parts.c',
  'message-part.c',
  'message-part-data.c',
  'message-part-serialize.c',
  'message-search.c',
  'message-size.c',
  'message-snippet.c',
  'ostream-dot.c',
  'qp-decoder.c',
  'qp-encoder.c',
  'quoted-printable.c',
  'rfc2231-parser.c',
  'rfc822-parser.c',
  include_directories: ['../lib-smtp'],
  dependencies: deps,
)

dep_mail = declare_dependency(
  link_with: lib_mail,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'istream-attachment-connector.h',
  'istream-attachment-extractor.h',
  'istream-binary-converter.h',
  'istream-dot.h',
  'istream-header-filter.h',
  'istream-qp.h',
  'mbox-from.h',
  'mail-html2text.h',
  'mail-types.h',
  'message-address.h',
  'message-binary-part.h',
  'message-date.h',
  'message-decoder.h',
  'message-header-decode.h',
  'message-header-encode.h',
  'message-header-hash.h',
  'message-header-parser.h',
  'message-id.h',
  'message-parser.h',
  'message-part.h',
  'message-part-data.h',
  'message-part-serialize.h',
  'message-search.h',
  'message-size.h',
  'message-snippet.h',
  'ostream-dot.h',
  'qp-decoder.h',
  'qp-encoder.h',
  'quoted-printable.h',
  'rfc2231-parser.h',
  'rfc822-parser.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  deps,
  dep_test,
  dep_mail,
]

tests = [
  'iostream-dot',
  'istream-attachment',
  'istream-binary-converter',
  'istream-dot',
  'istream-header-filter',
  'istream-qp-decoder',
  'istream-qp-encoder',
  'mail-html2text',
  'mbox-from',
  'message-address',
  'message-date',
  'message-decoder',
  'message-header-decode',
  'message-header-encode',
  'message-header-hash',
  'message-header-parser',
  'message-id',
  'message-parser',
  'message-part',
  'message-part-data',
  'message-part-serialize',
  'message-search',
  'message-size',
  'message-snippet',
  'ostream-dot',
  'qp-decoder',
  'qp-encoder',
  'quoted-printable',
  'rfc2231-parser',
  'rfc822-parser',
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
    suite: 'mail',
  )
endforeach

if get_option('fuzzing')
  fuzzers = [
    'message-date',
    'message-decoder',
    'message-parser',
    'qp-decoder',
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
        suite: 'mail',
        timeout: fuzzer_test_timeout,
        workdir: meson.current_build_dir(),
      )
    endif
  endforeach
endif
