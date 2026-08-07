# Prefer libunwind over backtrace()/execinfo.
ext_unwind = dependency('libunwind-generic', required: get_option('libunwind'))

conf.set(
  'HAVE_LIBUNWIND',
  ext_unwind.found(),
  description: 'Have libunwind',
)

summary({'libunwind': ext_unwind}, section: 'Features')
