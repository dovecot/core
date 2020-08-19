AC_DEFUN([DOVECOT_WANT_UNWIND], [
  have_libunwind=no
  AS_IF([test "$want_libunwind" != "no"], [
    PKG_CHECK_EXISTS([libunwind], [
      PKG_CHECK_MODULES([LIBUNWIND], [libunwind],[
        dnl see if there is target-specific library
        PKG_CHECK_MODULES([LIBUNWIND_GENERIC], [libunwind-generic],[
          have_libunwind=yes
          LIBUNWIND_LIBS="$LIBUNWIND_LIBS $LIBUNWIND_GENERIC_LIBS"
          AC_DEFINE([HAVE_LIBUNWIND],,[Define this if you have libunwind])
        ],[
           have_libunwind=no
           LIBUNWIND_LIBS=""
           LIBUNWIND_CFLAGS=""
        ])
      ])
     ])
  ])

  AC_MSG_CHECKING([whether we will be linking with libunwind]);
  AS_IF([test "$want_libunwind" = yes], [
     AS_IF([test "$have_libunwind" != yes], [
       AC_MSG_ERROR([Cannot find libunwind])
     ])
  ])
  AC_MSG_RESULT([$have_libunwind])
])
