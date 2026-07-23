subdir('ucd')

fs = import('fs')

unicode_data_filenames = [      # Generated source code filenames.
  'unicode-data-tables.c',
  'unicode-data-types.c',
  'unicode-data-tables.h',
  'unicode-data-types.h',
]
unicode_data_files = []         # Generated source code file objects.
unicode_data_dir = meson.current_source_dir()

# Check if the generated source code files are already available and create the list of
# source code file objects pointing to them.
foreach filename : unicode_data_filenames
  if not fs.is_file(filename)
    # Some or all of the unicode data generated source code files are not available. Reset
    # the list of file objects and break out so we can attempt to generate them below.
    unicode_data_files = []
    break
  endif
  unicode_data_files += files(filename)
endforeach

# A git checkout never ships the generated files, so a copy found here is a leftover from
# an autotools build. Ignore those and force the regeneration of the files.
if unicode_data_files.length() != 0 and have_git_tree
  warning('Found unicode data files in the source tree of a git checkout. ' +
          'Going to assume the unicode data files are leftover from autotools')
  unicode_data_files = []
endif

if unicode_data_files.length() == 0
  # The generated source code files are at least partially unavailable, but the downloaded
  # UCD files are available at this point. Attempt to generate the source code files.
  py = import('python')
  python = py.find_installation(
    'python3',
    modules: [
      'argparse',
      'bisect',
      'copy',
      're',
      'sys',
      'pathlib',
    ],
    required: true,
  )

  unicode_data_files = custom_target(
    'unicode-data',
    input: ucd_files,
    output: unicode_data_filenames,
    command: [
      python,
      files('unicode-ucd-compile.py'),
      ucd_files_dir,             # Directory with UCD files.
      meson.current_build_dir(), # Output directory for the generated source files.
    ],
    # Only the headers are installed, sources are compiled into libdovecot.
    install: true,
    install_dir: [false, false, dovecot_includedir, dovecot_includedir],
  )

  unicode_data_dir = meson.current_build_dir()
else
  install_headers(
    [unicode_data_files[2], unicode_data_files[3]],
    install_dir: dovecot_includedir,
  )
endif

# `meson dist` needs to copy the generated source files over from the build directory into
# the source directory in the tarball. This is so a tarball that ships with them can build
# without network access.
meson.add_dist_script(
  generated_dist_script,
  unicode_data_dir,        # Where the generated files can be found.
  'src/lib',               # Where the generated files should go in the tarball.
  unicode_data_filenames,  # The generated source filenames.
)

dep_unicode_data = declare_dependency(
  link_with: static_library(
    'unicode-data',
    [unicode_data_files[0], unicode_data_files[1]],
  ),
  sources: [unicode_data_files[2], unicode_data_files[3]],
  include_directories: include_directories('.'),
)

event_filter_filenames = [      # Generated source code filenames.
  'event-filter-lexer.c',
  'event-filter-parser.c',
  'event-filter-parser.h',
]
event_filter_files = []         # Generated source code file objects.
event_filter_dir = meson.current_source_dir()

# Check if the generated source code files are already available and create the list of
# source code file objects pointing to them.
foreach filename : event_filter_filenames
  if not fs.is_file(filename)
    # Some or all of the generated source code files are not available. Reset the list of
    # file objects and break out so we can attempt to generate them below.
    event_filter_files = []
    break
  endif
  event_filter_files += files(filename)
endforeach

# A git checkout never ships the generated files, so a copy found here is a leftover from
# an autotools build. Ignore those and force the regeneration of the files.
if event_filter_files.length() != 0 and have_git_tree
  warning('Found event filter files in the source tree of a git checkout. ' +
          'Going to assume the event filter files are leftover from autotools')
  event_filter_files = []
endif

if event_filter_files.length() == 0
  # The source files are at least partially unavailable. Attempt to generate them.
  prog_lex = find_program('flex', version: '>=2.6')
  prog_bison = find_program('bison', version: '>=3.6')

  event_filter_files += custom_target(
    'event-filter-lexer',
    input: 'event-filter-lexer.l',
    output: event_filter_filenames[0],
    command: [
      prog_lex,
      '-o', '@OUTPUT@',
      '@INPUT@',
    ],
  )

  event_filter_files += custom_target(
    'event-filter-parser',
    input: 'event-filter-parser.y',
    output: [
      event_filter_filenames[1],
      event_filter_filenames[2],
    ],
    command: [
      prog_bison,
      '--defines=@OUTPUT1@',
      '-o', '@OUTPUT0@',
      '@INPUT@',
    ],
    install: true,
    install_dir: [false, dovecot_includedir],
  )

  event_filter_dir = meson.current_build_dir()
else
  install_headers(event_filter_files[2], install_dir: dovecot_includedir)
endif

# `meson dist` needs to copy the generated source files over from the build directory into
# the source directory in the tarball. This is so a tarball that ships with them can build
# without network access.
meson.add_dist_script(
  generated_dist_script,
  event_filter_dir,        # Where the generated files can be found.
  'src/lib',               # Where the generated files should go in the tarball.
  event_filter_filenames,  # The generated source filenames.
)

liblib_sources = [
  'aqueue.c',
  'array.c',
  'askpass.c',
  'backtrace-string.c',
  'base32.c',
  'base64.c',
  'bitmap.c',
  'bits.c',
  'bsearch-insert-pos.c',
  'buffer-istream.c',
  'buffer.c',
  'child-wait.c',
  'connection.c',
  'cpu-count.c',
  'cpu-limit.c',
  'crc32.c',
  'data-stack.c',
  'eacces-error.c',
  'env-util.c',
  'event-filter.c',
  'event-log.c',
  'execv-const.c',
  'failures.c',
  'fd-util.c',
  'fdatasync-path.c',
  'fdpass.c',
  'file-cache.c',
  'file-copy.c',
  'file-create-locked.c',
  'file-dotlock.c',
  'file-lock.c',
  'file-set-size.c',
  'guid.c',
  'hash-format.c',
  'hash-method.c',
  'hash.c',
  'hash2.c',
  'hex-binary.c',
  'hex-dec.c',
  'hmac-cram-md5.c',
  'hmac.c',
  'home-expand.c',
  'hook-build.c',
  'hostpid.c',
  'idna-punycode.c',
  'idna.c',
  'imem.c',
  'ioloop-epoll.c',
  'ioloop-iolist.c',
  'ioloop-kqueue.c',
  'ioloop-notify-fd.c',
  'ioloop-notify-inotify.c',
  'ioloop-notify-kqueue.c',
  'ioloop-notify-none.c',
  'ioloop-poll.c',
  'ioloop-select.c',
  'ioloop.c',
  'iostream-proxy.c',
  'iostream-pump.c',
  'iostream-rawlog.c',
  'iostream-temp.c',
  'iostream.c',
  'ipwd.c',
  'iso8601-date.c',
  'istream-base64-decoder.c',
  'istream-base64-encoder.c',
  'istream-callback.c',
  'istream-chain.c',
  'istream-concat.c',
  'istream-crlf.c',
  'istream-data.c',
  'istream-failure-at.c',
  'istream-file.c',
  'istream-hash.c',
  'istream-limit.c',
  'istream-multiplex.c',
  'istream-nonuls.c',
  'istream-noop.c',
  'istream-rawlog.c',
  'istream-seekable.c',
  'istream-sized.c',
  'istream-tee.c',
  'istream-timeout.c',
  'istream-try.c',
  'istream-unix.c',
  'istream.c',
  'lib-event.c',
  'lib-signals.c',
  'lib.c',
  'log-throttle.c',
  'md4.c',
  'md5.c',
  'memarea.c',
  'mempool-allocfree.c',
  'mempool-alloconly.c',
  'mempool-datastack.c',
  'mempool-null.c',
  'mempool-system.c',
  'mempool-unsafe-datastack.c',
  'mempool.c',
  'mkdir-parents.c',
  'mmap-anon.c',
  'mmap-util.c',
  'module-dir.c',
  'mountpoint.c',
  'net.c',
  'nfs-workarounds.c',
  'numpack.c',
  'ostream-buffer.c',
  'ostream-failure-at.c',
  'ostream-file.c',
  'ostream-hash.c',
  'ostream-multiplex.c',
  'ostream-null.c',
  'ostream-rawlog.c',
  'ostream-unix.c',
  'ostream-wrapper.c',
  'ostream.c',
  'path-util.c',
  'pkcs5.c',
  'primes.c',
  'printf-format-fix.c',
  'priorityq.c',
  'process-stat.c',
  'process-title.c',
  'rand.c',
  'randgen.c',
  'read-full.c',
  'restrict-access.c',
  'restrict-process-size.c',
  'safe-memset.c',
  'safe-mkdir.c',
  'safe-mkstemp.c',
  'sendfile-util.c',
  'seq-range-array.c',
  'seq-set-builder.c',
  'sha1.c',
  'sha2.c',
  'sha3.c',
  'xxh64.c',
  'sleep.c',
  'sort.c',
  'stats-dist.c',
  'str-find.c',
  'str-parse.c',
  'str-sanitize.c',
  'str-table.c',
  'str.c',
  'strescape.c',
  'strfuncs.c',
  'strnum.c',
  'time-util.c',
  'unichar.c',
  'unicode-break.c',
  'unicode-data.c',
  'unicode-transform.c',
  'unix-socket-create.c',
  'unlink-directory.c',
  'unlink-old-files.c',
  'uri-util.c',
  'utc-mktime.c',
  'utc-offset.c',
  'version.c',
  'wildcard-match.c',
  'write-full.c',
  event_filter_files,
]

deps = [ext_zlib, dep_unicode_data, ext_dl, ext_unwind, ext_bsd]

lib_lib = static_library(
  'lib',
  dovecot_version_h,
  liblib_sources,
  dependencies: deps,
)

dep_lib = declare_dependency(
  link_with: lib_lib,
  include_directories: ['.'],
  dependencies: deps,
)

install_headers(
  'abnf.h',
  'aqueue.h',
  'array-decl.h',
  'array.h',
  'askpass.h',
  'backtrace-string.h',
  'base32.h',
  'base64.h',
  'bitmap.h',
  'bits.h',
  'bsearch-insert-pos.h',
  'buffer.h',
  'byteorder.h',
  'child-wait.h',
  'compat.h',
  'connection.h',
  'cpu-count.h',
  'cpu-limit.h',
  'crc32.h',
  'data-stack.h',
  'doc.h',
  'eacces-error.h',
  'env-util.h',
  'event-filter-private.h',
  'event-filter.h',
  'event-log.h',
  'execv-const.h',
  'failures-private.h',
  'failures.h',
  'fd-util.h',
  'fdatasync-path.h',
  'fdpass.h',
  'file-cache.h',
  'file-copy.h',
  'file-create-locked.h',
  'file-dotlock.h',
  'file-lock.h',
  'file-set-size.h',
  'fsync-mode.h',
  'guid.h',
  'hash-decl.h',
  'hash-format.h',
  'hash-method.h',
  'hash.h',
  'hash2.h',
  'hex-binary.h',
  'hex-dec.h',
  'hmac-cram-md5.h',
  'hmac.h',
  'home-expand.h',
  'hook-build.h',
  'hostpid.h',
  'idna-punycode.h',
  'idna.h',
  'imem.h',
  'ioloop-iolist.h',
  'ioloop-notify-fd.h',
  'ioloop-private.h',
  'ioloop.h',
  'iostream-multiplex-private.h',
  'iostream-private.h',
  'iostream-proxy.h',
  'iostream-pump.h',
  'iostream-rawlog-private.h',
  'iostream-rawlog.h',
  'iostream-temp.h',
  'iostream.h',
  'ipwd.h',
  'iso8601-date.h',
  'istream-base64.h',
  'istream-callback.h',
  'istream-chain.h',
  'istream-concat.h',
  'istream-crlf.h',
  'istream-failure-at.h',
  'istream-file-private.h',
  'istream-hash.h',
  'istream-multiplex.h',
  'istream-nonuls.h',
  'istream-private.h',
  'istream-rawlog.h',
  'istream-seekable.h',
  'istream-sized.h',
  'istream-tee.h',
  'istream-timeout.h',
  'istream-try.h',
  'istream-unix.h',
  'istream.h',
  'lib-event-private.h',
  'lib-event.h',
  'lib-signals.h',
  'lib.h',
  'llist.h',
  'log-throttle.h',
  'macros.h',
  'malloc-overflow.h',
  'md4.h',
  'md5.h',
  'memarea.h',
  'mempool.h',
  'mkdir-parents.h',
  'mmap-util.h',
  'module-context.h',
  'module-dir.h',
  'mountpoint.h',
  'net.h',
  'nfs-workarounds.h',
  'numpack.h',
  'ostream-failure-at.h',
  'ostream-file-private.h',
  'ostream-hash.h',
  'ostream-multiplex.h',
  'ostream-null.h',
  'ostream-private.h',
  'ostream-rawlog.h',
  'ostream-unix.h',
  'ostream-wrapper.h',
  'ostream.h',
  'path-util.h',
  'pkcs5.h',
  'primes.h',
  'printf-format-fix.h',
  'priorityq.h',
  'process-stat.h',
  'process-title.h',
  'randgen.h',
  'read-full.h',
  'restrict-access.h',
  'restrict-process-size.h',
  'safe-memset.h',
  'safe-mkdir.h',
  'safe-mkstemp.h',
  'sendfile-util.h',
  'seq-range-array.h',
  'seq-set-builder.h',
  'sha-common.h',
  'sha1.h',
  'sha2.h',
  'sha3.h',
  'sleep.h',
  'sort.h',
  'stats-dist.h',
  'str-find.h',
  'str-parse.h',
  'str-sanitize.h',
  'str-table.h',
  'str.h',
  'strescape.h',
  'strfuncs.h',
  'strnum.h',
  'time-util.h',
  'unichar.h',
  'unicode-break.h',
  'unicode-data-static.h',
  'unicode-data.h',
  'unicode-transform.h',
  'unix-socket-create.h',
  'unlink-directory.h',
  'unlink-old-files.h',
  'uri-util.h',
  'utc-mktime.h',
  'utc-offset.h',
  'version.h',
  'wildcard-match.h',
  'write-full.h',
  'xxh64.h',
  install_dir: dovecot_includedir,
)

tester_sources = [
  'test-aqueue.c',
  'test-array.c',
  'test-backtrace.c',
  'test-base32.c',
  'test-base64.c',
  'test-bitmap.c',
  'test-bits.c',
  'test-bsearch-insert-pos.c',
  'test-buffer-istream.c',
  'test-buffer.c',
  'test-byteorder.c',
  'test-connection.c',
  'test-crc32.c',
  'test-data-stack.c',
  'test-env-util.c',
  'test-event-category-register.c',
  'test-event-filter-expr.c',
  'test-event-filter-merge.c',
  'test-event-filter-parser.c',
  'test-event-filter.c',
  'test-event-flatten.c',
  'test-event-log.c',
  'test-failures.c',
  'test-fd-util.c',
  'test-file-cache.c',
  'test-file-create-locked.c',
  'test-guid.c',
  'test-hash-format.c',
  'test-hash-method.c',
  'test-hash.c',
  'test-hex-binary.c',
  'test-hmac.c',
  'test-idna.c',
  'test-idna-punycode.c',
  'test-imem.c',
  'test-ioloop.c',
  'test-iostream-proxy.c',
  'test-iostream-pump.c',
  'test-iostream-temp.c',
  'test-iso8601-date.c',
  'test-istream-base64-decoder.c',
  'test-istream-base64-encoder.c',
  'test-istream-chain.c',
  'test-istream-concat.c',
  'test-istream-crlf.c',
  'test-istream-failure-at.c',
  'test-istream-multiplex.c',
  'test-istream-noop.c',
  'test-istream-seekable.c',
  'test-istream-sized.c',
  'test-istream-tee.c',
  'test-istream-try.c',
  'test-istream-unix.c',
  'test-istream.c',
  'test-lib-event.c',
  'test-lib-signals.c',
  'test-lib.c',
  'test-llist.c',
  'test-log-throttle.c',
  'test-macros.c',
  'test-malloc-overflow.c',
  'test-memarea.c',
  'test-mempool-allocfree.c',
  'test-mempool-alloconly.c',
  'test-mempool.c',
  'test-multiplex.c',
  'test-net.c',
  'test-numpack.c',
  'test-ostream-buffer.c',
  'test-ostream-failure-at.c',
  'test-ostream-file.c',
  'test-ostream-multiplex.c',
  'test-path-util.c',
  'test-pkcs5.c',
  'test-primes.c',
  'test-printf-format-fix.c',
  'test-priorityq.c',
  'test-random.c',
  'test-seq-range-array.c',
  'test-seq-set-builder.c',
  'test-stats-dist.c',
  'test-str-find.c',
  'test-str-parse.c',
  'test-str-sanitize.c',
  'test-str-table.c',
  'test-str.c',
  'test-strescape.c',
  'test-strfuncs.c',
  'test-strnum.c',
  'test-time-util.c',
  'test-unichar.c',
  'test-unicode-break.c',
  'test-unicode-casemap.c',
  'test-unicode-data.c',
  'test-unicode-nf.c',
  'test-uri.c',
  'test-utc-mktime.c',
  'test-version.c',
  'test-wildcard-match.c',
]

test(
  'lib',
  executable(
    'test-lib',
    tester_sources,
    c_args: [f'-DUCD_DIR="@ucd_files_dir@"'],
    dependencies: [dep_test, dep_lib, dep_unicode_data],
  ),
  timeout: 0,
  suite: 'lib',
)

test(
  'cpu-limit',
  executable(
    'test-cpu-limit',
    'test-cpu-limit.c',
    dependencies: [dep_test, dep_lib],
  ),
  timeout: 0,
  suite: 'lib',
)
