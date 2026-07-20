is_gnu_source = cc.compiles(import('fs').read('is-glibc.c'), name: 'we are on glibc')

if is_gnu_source
  libc_prefix += '#define _GNU_SOURCE\n'
endif
