AC_DEFUN([DOVECOT_WANT_LZ4], [
  have_lz4=no

  AS_IF([test "$want_lz4" != "no"], [
    PKG_CHECK_MODULES([LZ4], [liblz4], [have_lz4=yes], [
      have_lz4=no

      AS_IF([test "$want_lz4" = "yes"], [
        AC_MSG_ERROR([cannot build with LZ4 support: lz4 library (liblz4) not found])
      ])
    ])
  ])

  AS_IF([test "$have_lz4" != "no"], [
    have_compress_lib=yes
    COMPRESS_LIBS="$COMPRESS_LIBS $LZ4_LIBS"
    AC_DEFINE(HAVE_LZ4,, [Define if you have lz4 library])

    AC_CHECK_LIB(lz4, LZ4_compress_default, [
      AC_DEFINE(HAVE_LZ4_COMPRESS_DEFAULT,, [
        Define if you have LZ4_compress_default
      ])
    ],, $LZ4_LIBS)
  ])
])
