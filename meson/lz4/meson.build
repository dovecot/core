opt_lz4 = get_option('lz4')
ext_lz4 = dependency('liblz4', required: opt_lz4)

conf.set('HAVE_LZ4', ext_lz4.found(), description: 'Have lz4 library')

if ext_lz4.found()
  conf.set(
    'HAVE_LZ4_COMPRESS_DEFAULT',
    cc.has_function('LZ4_compress_default', dependencies: ext_lz4),
    description: 'Have LZ4_compress_default',
  )
endif

summary({'lz4': ext_lz4}, section: 'Features')
