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
