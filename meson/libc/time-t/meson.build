
if cc.has_member('struct tm', 'tm_gmtoff', prefix: libc_prefix)
  conf.set10('HAVE_TM_GMTOFF', true)
endif

# Determine time_t signedness and size.
time_t_types = [
  {'name': 'long int',           'dspec': 'ld',  'xspec': 'lx',  'signed': true},
  {'name': 'int',                'dspec': 'd',   'xspec': 'x',   'signed': true},
  {'name': 'long long',          'dspec': 'lld', 'xspec': 'llx', 'signed': true},
  {'name': 'unsigned int',       'dspec': 'u',   'xspec': 'x',   'signed': false},
  {'name': 'unsigned long',      'dspec': 'lu',  'xspec': 'lx',  'signed': false},
  {'name': 'unsigned long long', 'dspec': 'llu', 'xspec': 'llx', 'signed': false},
]

fs = import('fs')
time_test_template = fs.read('time-test.c')
time_t_signed = false
foreach type : time_t_types
  name = type['name']
  dspec = type['dspec']
  xspec = type['xspec']
  signed = type['signed']

  if cc.run(
    time_test_template.format(name),
    name: f'time_t is @name@ check',
  ).returncode() == 0
    conf.set_quoted('PRIdTIME_T', dspec)
    conf.set_quoted('PRIxTIME_T', xspec)
    time_t_signed = signed

    break
  endif
endforeach

if not conf.has('PRIdTIME_T')
  error('Unsupported time_t type')
endif

# How large time_t values gmtime() accepts.
time_size_args = time_t_signed ? ['-DTIME_T_SIGNED'] : []
time_size_res = cc.run(
  fs.read('time_size.c'),
  args: time_size_args,
  name: 'time_t bits',
)
if time_size_res.compiled() and time_size_res.returncode() == 0
  conf.set('TIME_T_MAX_BITS', time_size_res.stdout())
else
  # Cross-compiling or the probe could not run; autotools assumes 31.
  conf.set('TIME_T_MAX_BITS', 31)
endif
