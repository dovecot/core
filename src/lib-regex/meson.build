deps = [dep_lib, ext_pcre]

lib_regex = static_library(
  'regex',
  ext_pcre.found() ? 'regex.c' : 'empty.c',
  dependencies: deps,
)

dep_regex = declare_dependency(
  link_with: lib_regex,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'dregex.h',
  install_dir: dovecot_includedir,
)

if ext_pcre.found()
  test(
    'regex',
    executable(
      'test-regex',
      'test-regex.c',
      dependencies: [deps, dep_test, dep_regex],
    ),
    suite: 'regex',
  )
endif
