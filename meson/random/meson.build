random_source = get_option('random-source')
have_getrandom = cc.has_function('getrandom', prefix: libc_prefix)
have_arc4random = cc.has_function('arc4random_buf', prefix: libc_prefix)

if not have_arc4random and ext_bsd.found()
  have_arc4random = cc.has_function(
    'arc4random_buf',
    prefix: libc_prefix + '#include <bsd/stdlib.h>\n',
    dependencies: ext_bsd,
  )
endif

have_decl_getrandom = cc.has_header_symbol('sys/random.h', 'getrandom')

conf.set('HAVE_GETRANDOM', have_getrandom)
conf.set('HAVE_ARC4RANDOM', have_arc4random)
conf.set10('HAVE_DECL_GETRANDOM', have_decl_getrandom)

fs = import('fs')

if fs.exists(random_source) and \
   fs.is_absolute(random_source) and \
   fs.is_dir(random_source) == false and \
   (fs.is_file(random_source) == false or fs.size(random_source) > 0)
  conf.set_quoted('DEV_URANDOM_PATH', random_source)
else
  error(f'Random source @random_source@ not usable')
endif

# Which generator randgen.c compiles in, following the same order it does. Anything else
# falls back to reading the device, so name that path by its own option value.
if get_option('fuzzing')
  # Fuzzing builds seed the deterministic KISS PRNG unconditionally.
  random_backend = 'kiss'
elif have_getrandom and have_decl_getrandom
  random_backend = 'getrandom'
elif have_arc4random
  random_backend = 'arc4random'
else
  random_backend = random_source
endif

# DEBUG builds also compile in KISS, but only use it when DOVECOT_SRAND asks for it.
if development_extra_checks == 'yes' and not get_option('fuzzing')
  random_backend += ' (or kiss, when DOVECOT_SRAND is set)'
endif

summary({'Random source' : random_backend}, section: 'Features')
