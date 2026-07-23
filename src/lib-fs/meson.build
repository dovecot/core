deps = [
  dep_test,
  dep_lib,
  dep_settings,
  dep_dict,
  dep_ssl_iostream,
]

lib_fs = static_library(
  'fs',
  'fs-api.c',
  'fs-dict.c',
  'fs-metawrap.c',
  'fs-posix.c',
  'fs-randomfail.c',
  'fs-sis.c',
  'fs-sis-common.c',
  'fs-sis-queue.c',
  'fs-test.c',
  'fs-test-async.c',
  'fs-wrapper.c',
  'istream-fs-file.c',
  'istream-fs-stats.c',
  'istream-metawrap.c',
  'ostream-cmp.c',
  'ostream-metawrap.c',
  dependencies: deps,
  c_args: f'-DMODULE_DIR="@dovecot_moduledir@"',
)

dep_fs = declare_dependency(
  link_with: lib_fs,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'fs-api.h',
  'fs-api-private.h',
  'fs-sis-common.h',
  'fs-wrapper.h',
  'fs-test.h',
  'istream-fs-file.h',
  'istream-fs-stats.h',
  'istream-metawrap.h',
  'ostream-metawrap.h',
  'ostream-cmp.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  dep_test,
  dep_fs,
  dep_lib,
  dep_settings,
]

tests = ['metawrap', 'posix', 'abort']

foreach test_name : tests
  exe = f'test-fs-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'fs',
  )
endforeach
