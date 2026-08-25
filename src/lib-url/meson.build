deps = [dep_lib]

lib_url = static_library(
  'url',
  'uri-util.c',
  'http-url.c',
  dependencies: deps,
)

dep_url = declare_dependency(
  link_with: lib_url,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'uri-util.h',
  'http-url.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_test, dep_url]

tests = ['uri-util', 'http-url']

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
    suite: 'url',
  )
endforeach
