# Probe for what the compiler supports rather than based on what meson's b_sanitize value
# contains.

conf.set(
  'HAVE_UNDEFINED_SANITIZER',
  cc.compiles(
    import('fs').read('no-sanitize.c'),
    args: '-Werror',
    name: 'no_sanitize attribute',
  ),
  description: 'If compiler supports undefined sanitizers',
)

# __attribute__((no_sanitize_undefined)) on gcc and no_sanitize("undefined") on clang.
conf.set(
  'HAVE_FSANITIZE_UNDEFINED',
  cc.has_argument('-fsanitize=undefined'),
  description: 'If compiler has -fsanitize=undefined',
)

# clang-only; gcc rejects both this flag and no_sanitize("integer").
conf.set(
  'HAVE_FSANITIZE_INTEGER',
  cc.has_argument('-fsanitize=integer'),
  description: 'If compiler has -fsanitize=integer',
)

b_sanitize = get_option('b_sanitize')
if meson.version().version_compare('>=1.8')
  # b_sanitize is a list of strings from 1.8 on.
  sanitizers = b_sanitize
else
  # b_sanitize is a comma-separated string before meson 1.8.
  sanitizers = b_sanitize.split(',')
endif

have_ubsan = 'undefined' in sanitizers

# clang keeps the sanitizer runtimes, e.g. __asan_report_* and __ubsan_handle_*, out of
# shared libraries and expects the executable to provide them, so -Wl,--no-undefined makes
# libdovecot.so fail to link. gcc links the runtime into the shared library so it is
# unaffected.
if have_clang and get_option('b_lundef')
  foreach sanitizer : sanitizers
    if sanitizer != 'none'
      error(f'The @sanitizer@ sanitizer requires -Db_lundef=false with clang')
    endif
  endforeach
endif

if have_ubsan
  # These are project arguments, which meson emits after that base argument, so the
  # -fno-sanitize= exclusions take precedence.
  ubsan_args = [
    '-fno-sanitize=function',
    '-fno-sanitize=vptr',
    '-fno-sanitize=nonnull-attribute',
    '-fsanitize=implicit-integer-truncation',
    '-fsanitize=local-bounds',
    '-fsanitize=integer',
    '-fsanitize=nullability',
    '-fno-omit-frame-pointer',
  ]

  add_project_arguments(cc.get_supported_arguments(ubsan_args), language: 'c')
  add_project_arguments(cxx.get_supported_arguments(ubsan_args), language: 'cpp')
endif
