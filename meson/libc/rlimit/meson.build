fs = import('fs')

try_rlimit_restypes = [
  'RLIMIT_AS',
  'RLIMIT_NPROC',
  'RLIMIT_CORE',
]

rlimit_test_template = fs.read('rlimit.c')

foreach type : try_rlimit_restypes
  rlimit_test_program = rlimit_test_template.format(libc_prefix, type)

  if cc.compiles(rlimit_test_program, name: f'@type@ exists')
    conf.set10(f'HAVE_@type@', true)
  endif
endforeach
