AC_DEFUN([DOVECOT_ZLIB], [
  PKG_CHECK_MODULES([ZLIB], [zlib], [
    have_compress_lib=yes
    COMPRESS_LIBS="$COMPRESS_LIBS $ZLIB_LIBS"
  ], [
    AC_MSG_ERROR([cannot build with zlib support: zlib library not found])
  ])
])
