AC_DEFUN([DOVECOT_WANT_ZLIB], [
  have_zlib=no

  AS_IF([test "$want_zlib" != "no"], [
    PKG_CHECK_MODULES([ZLIB], [zlib], [have_zlib=yes], [
      have_zlib=no

      AS_IF([test "$want_zlib" = "yes"], [
        AC_MSG_ERROR([cannot build with zlib support: zlib library not found])
      ])
    ])
  ])

  AS_IF([test "$have_zlib" != "no"], [
    have_compress_lib=yes
    COMPRESS_LIBS="$COMPRESS_LIBS $ZLIB_LIBS"
    AC_DEFINE(HAVE_ZLIB,, [Define if you have zlib library])
  ])
])
