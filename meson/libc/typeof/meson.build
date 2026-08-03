# typeof() is a GNU extension, standardised only in C23, so it is probed rather than
# assumed. src/lib/{array,hash,module-context}.h drop their compile-time type checks
# without it, and compat.h keys HAVE_TYPE_CHECKS off it.
conf.set(
  'HAVE_TYPEOF',
  cc.compiles(import('fs').read('typeof.c'), name: 'typeof()'),
  description: 'Have typeof()',
)
