global_args = ['-DHAVE_CONFIG_H', '-I.']

# Compiler arguments to improve the debugging experience. -fvar-tracking-assignments is
# more compilation-expensive but provides better debugging info.
if get_option('buildtype') in ['debug', 'debugoptimized']
  global_args += [
    '-g3',
    '-ggdb3',
    '-gdwarf-5',
    '-fvar-tracking',
    '-fvar-tracking-assignments',
  ]
endif

# Override some built-in meson flags e.g. -O2 with -Og for a better debugging experience.
if get_option('buildtype') == 'debug'
  global_args += [
    '-Og',
    '-fno-inline',
  ]
endif

# Meson passes the source files to the compiler with paths relative to the build directory,
# so __FILE__ would be e.g. "../../dovecot/src/lib/ioloop.c". Strip the source root from it
# to get "src/lib/ioloop.c" in panic messages and logs regardless of the build directory's
# location. The absolute path is mapped as well in case it is used.
fs = import('fs')
global_args += [
  '-fmacro-prefix-map=' + fs.relative_to(
    meson.project_source_root(),
    meson.project_build_root(),
  ) + '/=',
  '-fmacro-prefix-map=' + meson.project_source_root() + '/=',
]

c_args = [
  '-Wmissing-prototypes',
  '-Wmissing-declarations',
  '-Wpointer-arith',
  '-Wchar-subscripts',
  '-Wformat=2',
  '-Wbad-function-cast',
  '-Wstrict-aliasing=2',
]

if have_clang
  c_args += '-Wno-duplicate-decl-specifier'
else
  c_args += '-fno-builtin-strftime'
endif

add_project_arguments(cc.get_supported_arguments(global_args), language: 'c')
add_project_arguments(cxx.get_supported_arguments(global_args), language: 'cpp')
add_project_arguments(cc.get_supported_arguments(c_args), language: 'c')
