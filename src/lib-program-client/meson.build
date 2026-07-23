deps = [
  dep_lib,
  dep_settings,
  dep_dns_client,
  dep_mail,
]

lib_program_client = static_library(
  'program-client',
  'program-client.c',
  'program-client-local.c',
  'program-client-remote.c',
  dependencies: [deps, dir_defines],
)

dep_program_client = declare_dependency(
  link_with: lib_program_client,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'program-client.h',
  install_dir: dovecot_includedir,
)

tests = ['local', 'unix', 'net']

test_deps = [
  deps,
  dep_program_client,
  dep_test,
]

foreach test_name : tests
  exe = f'test-program-client-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'program-client',
  )
endforeach
