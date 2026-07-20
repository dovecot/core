fs = import('fs')

# Enable large-file support before measuring off_t/uoff_t.
largefile_args = []
if cc.sizeof('off_t') < 8
  if cc.sizeof('off_t', args: ['-D_LARGEFILE_SOURCE']) == 8
    largefile_args = ['-D_LARGEFILE_SOURCE']
  elif cc.sizeof('off_t', args: ['-D_LARGEFILE_SOURCE', '-D_FILE_OFFSET_BITS=64']) == 8
    largefile_args = ['-D_LARGEFILE_SOURCE', '-D_FILE_OFFSET_BITS=64']
  endif
  add_project_arguments(largefile_args, language: ['c', 'cpp'])
endif

# 'signed' here asks for a signedness probe. It is only meaningful for integer types, so
# it is off for void * - ISUNSIGNED() on a pointer is not a constant expression and the
# answer would say nothing anyway.
types = [
  {'name': 'int',       'symbol': 'INT',       'max': '',      'signed': false},
  {'name': 'long',      'symbol': 'LONG',      'max': '',      'signed': false},
  {'name': 'void *',    'symbol': 'VOID_P',    'max': '',      'signed': false},
  {'name': 'long long', 'symbol': 'LONG_LONG', 'max': '',      'signed': false},
  {'name': 'size_t',    'symbol': 'SIZE_T',    'max': 'SIZE' , 'signed': true},
  {'name': 'ssize_t',   'symbol': 'SSIZE_T',   'max': 'SSIZE', 'signed': true},
  {'name': 'off_t',     'symbol': 'OFF_T',     'max': '',      'signed': false},
]

is_signed_template = fs.read('is-signed.c')

foreach type : types
  name = type['name']
  symbol = type['symbol']
  has_max = type['max']
  signed = type['signed']

  size = cc.sizeof(name, args: largefile_args)
  if size > -1
    conf.set10(f'HAVE_@symbol@', true)
    conf.set(f'SIZEOF_@symbol@', size)

    if signed
      is_signed_program = is_signed_template.format(name)

      if cc.compiles(
        is_signed_program,
        args: largefile_args,
        name: f'@name@ is signed',
      )
        conf.set(f'@symbol@_SIGNED', true)
      else
        conf.set(f'@symbol@_UNSIGNED', true)
      endif
    endif

    if has_max != ''
      prefix = ['#include <stdint.h>', '#include <limits.h>']

      if cc.get_define(f'@has_max@_MAX', prefix: prefix) != ''
        conf.set(f'@symbol@_MAX', f'@has_max@_MAX')
      endif
    endif
  endif
endforeach

# Which limits and printf specifiers apply to off_t/uoff_t follows from off_t's exact
# type, not from its width: on ILP32 with large-file support off_t is long long while
# sizeof(long) is 4, and a purely size-based mapping picks LONG_MAX there.
is_type_template = fs.read('is-type.c')

off_t_types = [
  {
    'name': 'long',
    'off_t_max': 'LONG_MAX',
    'uoff_t_max': 'ULONG_MAX',
    'uoff_t_symbol': 'UOFF_T_LONG',
    'dspec': 'ld',
    'uspec': 'lu',
  },
  {
    'name': 'int',
    'off_t_max': 'INT_MAX',
    'uoff_t_max': 'UINT_MAX',
    'uoff_t_symbol': 'UOFF_T_INT',
    'dspec': 'd',
    'uspec': 'u',
  },
  {
    'name': 'long long',
    'off_t_max': 'LLONG_MAX',
    'uoff_t_max': 'ULLONG_MAX',
    'uoff_t_symbol': 'UOFF_T_LONG_LONG',
    'dspec': 'lld',
    'uspec': 'llu',
  },
]

off_t_type = {}
foreach type : off_t_types
  name = type['name']

  if cc.compiles(
    is_type_template.format('off_t', name),
    args: largefile_args,
    name: f'off_t is @name@',
  )
    off_t_type = type
    break
  endif
endforeach

if off_t_type == {}
  error('Unsupported off_t type')
endif

limits_prefix = '\n'.join(
  [
    '#include <limits.h>',
    '#include <sys/types.h>',
  ],
)

# uoff_t is a Dovecot typedef on every platform we know of, but keep a check for a native
# one: compat.h skips its own typedef when HAVE_UOFF_T is set.
have_uoff_t = cc.has_type('uoff_t', prefix: limits_prefix, args: largefile_args)
conf.set('HAVE_UOFF_T', have_uoff_t, description: 'Have a native uoff_t type')

if not have_uoff_t
  conf.set(off_t_type['uoff_t_symbol'], '')
endif

conf.set_quoted('PRIdOFF_T', off_t_type['dspec'])
conf.set_quoted('PRIuUOFF_T', off_t_type['uspec'])

# Only define the maxima the platform does not already provide.
if not cc.compiles(
  f'@limits_prefix@\nint main(void) { off_t i = OFF_T_MAX; (void)i; return 0; }',
  args: largefile_args,
  name: 'OFF_T_MAX is predefined',
)
  conf.set('OFF_T_MAX', off_t_type['off_t_max'])
endif

if not cc.compiles(
  f'@limits_prefix@\nint main(void) { uoff_t i = UOFF_T_MAX; (void)i; return 0; }',
  args: largefile_args,
  name: 'UOFF_T_MAX is predefined',
)
  conf.set('UOFF_T_MAX', off_t_type['uoff_t_max'])
endif
