opt_bzlib = get_option('bzlib')
ext_bzlib = cc.find_library('bz2', has_headers: ['bzlib.h'], required: opt_bzlib)

if ext_bzlib.found() and not cc.has_function(
  'BZ2_bzdopen',
  dependencies: ext_bzlib,
  required: opt_bzlib,
)
  ext_bzlib = dependency('', required: false)
endif

conf.set('HAVE_BZLIB', ext_bzlib.found(), description: 'Have bzlib library')
summary({'bzlib': ext_bzlib}, section: 'Features')
