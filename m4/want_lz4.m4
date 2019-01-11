AC_DEFUN([DOVECOT_WANT_LZ4], [
  AS_IF([test "$want_lz4" != "no"], [
    AC_CHECK_HEADER(lz4.h, [
      AC_CHECK_LIB(lz4, LZ4_compress, [
        have_lz4=yes
        have_compress_lib=yes
        AC_DEFINE(HAVE_LZ4,, [Define if you have lz4 library])
        COMPRESS_LIBS="$COMPRESS_LIBS -llz4"
      ], [
        AS_IF([test "$want_lz4" = "yes"], [
          AC_ERROR([Can't build with lz4 support: liblz4 not found])
        ])
      ])
      AC_CHECK_LIB(lz4, LZ4_compress_default, [
        AC_DEFINE(HAVE_LZ4_COMPRESS_DEFAULT,,
          [Define if you have LZ4_compress_default])
      ], [
      ])
    ], [
      AS_IF([test "$want_lz4" = "yes"], [
        AC_ERROR([Can't build with lz4 support: lz4.h not found])
      ])
    ])
  ])
])
