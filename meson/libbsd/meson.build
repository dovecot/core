libbsd_option = get_option('libbsd')
ext_bsd = dependency('', required: false)

if libbsd_option.allowed()
  # Only the find_library() fallback carries the feature: making the pkg-config attempt required
  # too would abort on a libbsd installed without its .pc file.
  ext_bsd = dependency('libbsd', required: false)

  if not ext_bsd.found()
    ext_bsd = cc.find_library(
      'bsd',
      has_headers: ['bsd/stdlib.h', 'bsd/unistd.h'],
      required: libbsd_option,
    )
  endif
endif

conf.set(
  'HAVE_LIBBSD',
  ext_bsd.found(),
  description: 'Have libbsd',
)

summary({'libbsd': ext_bsd}, section: 'Features')
