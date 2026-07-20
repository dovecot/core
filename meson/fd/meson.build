fs = import('fs')

fdpass_c_file = meson.global_source_root() / 'src' / 'lib' / 'fdpass.c'
fdpass_include = meson.global_source_root() / 'src' / 'lib'

fd_pass_check = fs.read('fd-passing.c')
args = [f'-I@fdpass_include@', fdpass_c_file]

if cc.run(fd_pass_check, args: args, name: 'fd passing').returncode() != 0
  args += '-DBUGGY_CMSG_MACROS'
  if cc.run(fd_pass_check, args: args, name: 'fd passing').returncode() == 0
    conf.set10('BUGGY_CMSG_MACROS', true)
  endif
endif

if system == 'darwin'
  conf.set10('BUGGY_CMSG_MACROS', true)
endif
