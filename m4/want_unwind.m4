AC_DEFUN([DOVECOT_WANT_UNWIND], [
  have_libunwind=no
  AS_IF([test "$want_libunwind" != "no"], [
    PKG_CHECK_EXISTS([libunwind], [
      PKG_CHECK_MODULES([LIBUNWIND], [libunwind-generic],[
        have_libunwind=yes
	AC_DEFINE([HAVE_LIBUNWIND],,[Define this if you have libunwind])
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
