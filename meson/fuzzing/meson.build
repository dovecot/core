conf.set(
  'HAVE_LOCAL_FUZZER',
  get_option('fuzzing-local'),
  description: 'Enable fuzzer suitable only for local use (not for e.g. OSS-Fuzz)',
)

if get_option('fuzzing')
  fuzzer_engine = get_option('fuzzing-engine')
  if fuzzer_engine == ''
    error('Fuzzing requested but no fuzzing engine was given')
  endif

  # Only clang ships libFuzzer, and the instrumentation flags below are added for both
  # languages, so check both. has_argument(required: true) would report this as an unusable
  # argument without hinting that the real cause is a non-clang compiler. Note that meson
  # dist forwards the -D options of a build directory but not its CC/CXX environment, so
  # select clang with --native-file if the tarball is meant to be checked with fuzzing on.
  foreach arg : ['-fsanitize=fuzzer-no-link', '-fPIE', fuzzer_engine]
    foreach language, compiler : {'C': cc, 'C++': cxx}
      if not compiler.has_argument(arg)
        error(
          'Fuzzing needs clang but the @0@ compiler is @1@ and rejects @2@'.format(
            language,
            compiler.get_id(),
            arg,
          ),
        )
      endif
    endforeach
  endforeach

  # The instrumentation leaves __sanitizer_cov_* undefined in libdovecot.so and expects it
  # to be resolved from the executable at load time, so meson's default -Wl,--no-undefined
  # cannot work, so ensure b_lundef is false.
  if get_option('b_lundef')
    error('Fuzzing requires -Db_lundef=false')
  endif

  # Meson warns here to prefer the built-in b_sanitize option, but until meson 1.8 that option
  # is a fixed set of choices with no "fuzzer-no-link" among them, so the flag has to be passed
  # by hand. The warning is expected and cannot be suppressed.
  #   https://mesonbuild.com/Release-notes-for-1-8-0.html (b_sanitize becomes free-form)
  #   https://github.com/mesonbuild/meson/issues/10685 (no way to silence the warning)
  add_project_arguments(
    '-fsanitize=fuzzer-no-link',
    '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
    language: ['c', 'cpp'],
  )

  # Needed even though the instrumentation itself is a compile-time affair: at link time this
  # pulls the sanitizer runtime into every executable, which is where the weak __sanitizer_cov_*
  # stubs come from that the instrumented libdovecot.so leaves undefined.
  add_project_link_arguments(
    '-fsanitize=fuzzer-no-link',
    language: ['c', 'cpp'],
  )

  ext_fuzzer = declare_dependency(
    compile_args: ['-fPIE', '-DPIE'],
    link_args: [fuzzer_engine],
  )

  # A bounded run doubles as a regression test: libFuzzer exits non-zero on a crash, and a
  # fixed seed keeps it reproducible. Callers pass workdir: meson.current_build_dir() so
  # the crash-* reproducer that libFuzzer writes on failure lands in the build tree.
  fuzzer_test_runs = get_option('fuzzing-test-runs')
  fuzzer_test_args = [f'-runs=@fuzzer_test_runs@', '-seed=1']
  fuzzer_test_timeout = 300
endif
