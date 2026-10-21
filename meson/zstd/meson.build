opt_zstd = get_option('zstd')
ext_zstd = dependency('libzstd', required: opt_zstd)

conf.set('HAVE_ZSTD', ext_zstd.found(), description: 'Have zstd library')

if ext_zstd.found()
  conf.set(
    'HAVE_ZSTD_GETERRORCODE',
    cc.has_function('ZSTD_getErrorCode', dependencies: ext_zstd),
    description: 'Have ZSTD_getErrorCode',
  )

  # C code compares these against 1, so they need to be defined as 0 or 1.
  foreach decl : ['ZSTD_error_parameter_unsupported', 'ZSTD_minCLevel']
    conf.set10(
      'HAVE_DECL_' + decl.to_upper(),
      cc.has_header_symbol(
        'zstd_errors.h',
        decl,
        prefix: '#include <zstd.h>',
        dependencies: ext_zstd,
      ),
      description: f'Have declaration of @decl@',
    )
  endforeach
endif

summary({'zstd': ext_zstd}, section: 'Features')
