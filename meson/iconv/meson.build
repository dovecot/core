# iconv() is part of libc on GNU, but is a separate libiconv on musl, the BSDs and macOS.
# lib-charset compiles charset-iconv.c unconditionally, so this is not optional.
ext_iconv = dependency('iconv', required: true)
conf.set('HAVE_ICONV', ext_iconv.found(), description: 'Have iconv()')
summary({'iconv': ext_iconv}, section: 'Features')
