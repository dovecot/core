AC_DEFUN([DOVECOT_WANT_BZLIB], [
  if test "$want_bzlib" != "no"; then
    AC_CHECK_HEADER(bzlib.h, [
      AC_CHECK_LIB(bz2, BZ2_bzdopen, [
        have_bzlib=yes
        have_compress_lib=yes
        AC_DEFINE(HAVE_BZLIB,, [Define if you have bzlib library])
        COMPRESS_LIBS="$COMPRESS_LIBS -lbz2"
      ], [
        if test "$want_bzlib" = "yes"; then
          AC_ERROR([Can't build with bzlib support: libbz2 not found])
        fi
      ])
    ], [
      if test "$want_bzlib" = "yes"; then
        AC_ERROR([Can't build with bzlib support: bzlib.h not found])
      fi
    ])
  fi
])
