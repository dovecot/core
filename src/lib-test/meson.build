dovecot_test_dir = dovecot_build_root / '.test'

lib_test = static_library(
  'dtest',
  'fuzzer.c',
  'ostream-final-trickle.c',
  'test-common.c',
  'test-dir.c',
  'test-istream.c',
  'test-ostream.c',
  'test-subprocess.c',
  # This is the only place where we directly use an include dir because lib-test is
  # loaded before lib due to the circular dependency between the two
  # libraries. Everywhere else we should use dependency objects to represent
  # dependencies for things like include dirs, libraries, linking arguments, etc...
  include_directories: ['../lib'],
)

dep_test = declare_dependency(
  link_with: lib_test,
  include_directories: include_directories('.'),
  compile_args: [f'-DTEST_DIR="@dovecot_test_dir@"'],
)

install_headers(
  'fuzzer.h',
  'ostream-final-trickle.h',
  'test-common.h',
  'test-private.h',
  'test-dir.h',
  'test-subprocess.h',
  install_dir: dovecot_includedir,
)
