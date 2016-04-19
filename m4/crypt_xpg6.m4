dnl * Check for crypt() if unistd.h compiles with _XOPEN_SOURCE + _XPG6
dnl * Add other macros there too "just in case".
AC_DEFUN([DOVECOT_CRYPT_XPG6], [
  AC_CACHE_CHECK([if we should use _XPG6 macro for crypt()],i_cv_use_xpg6_crypt,[
    AC_TRY_COMPILE([
      #define _XOPEN_SOURCE 4
      #define _XOPEN_SOURCE_EXTENDED 1
      #define _XOPEN_VERSION 4
      #define _XPG4_2
      #define _XPG6
      #include <unistd.h>
    ], [
      crypt("a", "b");
    ], [
      i_cv_use_xpg6_crypt=yes
    ], [
      i_cv_use_xpg6_crypt=no
    ])
  ])
  if test $i_cv_use_xpg6_crypt = yes; then
    AC_DEFINE(CRYPT_USE_XPG6,, [Define if _XPG6 macro is needed for crypt()])
  fi
])
