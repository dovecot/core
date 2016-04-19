AC_DEFUN([DOVECOT_WANT_LZMA], [
  if test "$want_lzma" != "no"; then
    AC_CHECK_HEADER(lzma.h, [
      AC_CHECK_LIB(lzma, lzma_stream_decoder, [
        have_lzma=yes
        have_compress_lib=yes
        AC_DEFINE(HAVE_LZMA,, [Define if you have lzma library])
        COMPRESS_LIBS="$COMPRESS_LIBS -llzma"
      ], [
        if test "$want_lzma" = "yes"; then
          AC_ERROR([Can't build with lzma support: liblzma not found])
        fi
      ])
    ], [
      if test "$want_lzma" = "yes"; then
        AC_ERROR([Can't build with lzma support: lzma.h not found])
      fi
    ])
  fi
])
