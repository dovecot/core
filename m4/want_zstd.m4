AC_DEFUN([DOVECOT_WANT_ZSTD], [
  AS_IF([test "$want_zstd" != "no"], [
    AC_CHECK_HEADER(zstd.h, [
      AC_CHECK_LIB(zstd, ZSTD_compressStream, [
        have_zstd=yes
        have_compress_lib=yes
        AC_DEFINE(HAVE_ZSTD,, [Define if you have zstd library])
        COMPRESS_LIBS="$COMPRESS_LIBS -lzstd"
      ], [
        AS_IF([test "$want_zstd" = "yes"], [
          AC_ERROR([Can't build with zstd support: libzstd not found])
        ])
      ])
    ], [
      AS_IF([test "$want_zstd" = "yes"], [
        AC_ERROR([Can't build with zstd support: zstd.h not found])
      ])
    ])
  ])
])
