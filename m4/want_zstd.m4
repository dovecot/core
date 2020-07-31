AC_DEFUN([DOVECOT_WANT_ZSTD], [
  have_zstd=no

  AS_IF([test $want_zstd = yes], [
    PKG_CHECK_MODULES([ZSTD], [libzstd], [have_zstd=yes], [AC_MSG_ERROR([libzstd not found])])
  ], [AS_IF([test $want_zstd != no], [
      PKG_CHECK_MODULES([ZSTD], [libzstd], [have_zstd=yes], [have_zstd=no])
    ])
  ])

  AS_IF([test $have_zstd = yes], [
    have_compress_lib=yes
    COMPRESS_LIBS="$COMPRESS_LIBS $ZSTD_LIBS"
    AC_DEFINE([HAVE_ZSTD], [], [Define if you have ZSTD library])
    AC_CHECK_DECLS([ZSTD_error_parameter_unsupported], [], [], [[#include <zstd_errors.h>]])
    AC_CHECK_LIB([zstd], [ZSTD_getErrorCode], [
	AC_DEFINE([HAVE_ZSTD_GETERRORCODE], [1], [Whether zstd has ZSTD_getErrorCode])
    ], [])
  ])

  AM_CONDITIONAL([BUILD_ZSTD], test "$have_zstd" = "yes")
])
