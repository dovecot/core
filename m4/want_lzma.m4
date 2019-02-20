AC_DEFUN([DOVECOT_WANT_LZMA], [
  AS_IF([test "$want_lzma" != "no"], [
    AC_CHECK_HEADER(lzma.h, [
      AC_CHECK_LIB(lzma, lzma_stream_decoder, [
        have_lzma=yes
        have_compress_lib=yes
        AC_DEFINE(HAVE_LZMA,, [Define if you have lzma library])
        COMPRESS_LIBS="$COMPRESS_LIBS -llzma"
      ], [
        AS_IF([test "$want_lzma" = "yes"], [
          AC_ERROR([Can't build with lzma support: liblzma not found])
        ])
      ])
    ], [
      AS_IF([test "$want_lzma" = "yes"], [
        AC_ERROR([Can't build with lzma support: lzma.h not found])
      ])
    ])
  ])
])
