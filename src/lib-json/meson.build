deps = [dep_lib, ext_math]

lib_json = static_library(
  'json',
  'json-syntax.c',
  'json-types.c',
  'json-pointer.c',
  'json-tree.c',
  'json-tree-io.c',
  'json-tree-query.c',
  'json-parser.c',
  'json-generator.c',
  'json-istream.c',
  'json-ostream.c',
  'json-text.c',
  'istream-json-string.c',
  dependencies: deps,
)

dep_json = declare_dependency(
  link_with: lib_json,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'json-syntax.h',
  'json-types.h',
  'json-pointer.h',
  'json-tree.h',
  'json-tree-io.h',
  'json-tree-query.h',
  'json-parser.h',
  'json-generator.h',
  'json-istream.h',
  'json-ostream.h',
  'json-text.h',
  'istream-json-string.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_test, dep_json, dep_charset]

bin_json_format = executable(
  'json-format',
  'json-format.c',
  dependencies: test_deps,
)

tests = [
  'parser',
  'generator',
  'io',
  'istream',
  'ostream',
  'tree',
  'tree-io',
  'tree-query',
]

foreach test_name : tests
  exe = f'test-json-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'json',
  )
endforeach

test(
  'istream-json-string',
  executable(
    'test-istream-json-string',
    'test-istream-json-string.c',
    dependencies: test_deps,
  ),
  suite: 'json',
)

if get_option('fuzzing')
  fuzzers = [
    'json-istream',
    'istream-json-string',
    'json-pointer',
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
        suite: 'json',
        timeout: fuzzer_test_timeout,
        workdir: meson.current_build_dir(),
      )
    endif
  endforeach
endif
