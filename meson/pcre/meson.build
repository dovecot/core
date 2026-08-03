opt_pcre = get_option('pcre')
ext_pcre = dependency('libpcre2-32', required: opt_pcre)

conf.set(
  'HAVE_LIBPCRE',
  ext_pcre.found(),
  description: 'Have libpcre2 backed regular expressions',
)

if ext_pcre.found()
  # pcre2.h needs PCRE2_CODE_UNIT_WIDTH before it will declare anything; 0 asks for the
  # width-agnostic names.
  conf.set(
    'HAVE_PCRE2_SUBSTITUTE_CALLOUT_BLOCK',
    cc.has_header_symbol(
      'pcre2.h',
      'pcre2_substitute_callout_block',
      prefix: '#define PCRE2_CODE_UNIT_WIDTH 0',
      dependencies: ext_pcre,
    ),
    description: 'Have pcre2_substitute_callout_block',
  )
endif

summary({'PCRE': ext_pcre}, section: 'Features')
