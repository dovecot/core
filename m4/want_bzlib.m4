AC_DEFUN([DOVECOT_WANT_BZLIB], [
  AS_IF([test "$want_bzlib" != "no"], [
    AC_CHECK_HEADER(bzlib.h, [
      AC_CHECK_LIB(bz2, BZ2_bzdopen, [
        have_bzlib=yes
        have_compress_lib=yes
        AC_DEFINE(HAVE_BZLIB,, [Define if you have bzlib library])
        COMPRESS_LIBS="$COMPRESS_LIBS -lbz2"
      ], [
        AS_IF([test "$want_bzlib" = "yes"], [
          AC_ERROR([Can't build with bzlib support: libbz2 not found])
        ])
      ])
    ], [
      AS_IF([test "$want_bzlib" = "yes"], [
        AC_ERROR([Can't build with bzlib support: bzlib.h not found])
      ])
    ])
  ])
])
