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
  ])

  AM_CONDITIONAL([BUILD_ZSTD], test "$have_zstd" = "yes")
])
