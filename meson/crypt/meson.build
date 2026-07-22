fs = import('fs')

ext_crypt = declare_dependency()

# crypt() is in libc on some platforms and in libcrypt on others.
if not cc.has_function('crypt')
  ext_libcrypt = cc.find_library('crypt', required: false)
  if not cc.has_function('crypt', dependencies: ext_libcrypt)
    error('crypt() was not found')
  endif
  ext_crypt = ext_libcrypt
endif

# Some platforms (Solaris/AIX) only declare crypt() when _XPG6 is defined. Which library
# crypt() lives in is a separate question, so this is checked on its own: a platform can
# need both -lcrypt and _XPG6, and glibc needs the macro without needing the library.
conf.set(
  'CRYPT_USE_XPG6',
  cc.compiles(fs.read('crypt-xpg6.c'), name: '_XPG6 needed for crypt()'),
  description: 'Define if _XPG6 macro is needed for crypt()',
)
