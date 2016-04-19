AC_DEFUN([DOVECOT_WANT_ZLIB], [
  if test "$want_zlib" != "no"; then
    AC_CHECK_HEADER(zlib.h, [
      have_zlib=yes
      have_compress_lib=yes
      AC_DEFINE(HAVE_ZLIB,, [Define if you have zlib library])
      COMPRESS_LIBS="$COMPRESS_LIBS -lz"
    ], [
      if test "$want_zlib" = "yes"; then
        AC_ERROR([Can't build with zlib support: zlib.h not found])
      fi
    ])
  fi
])
