AC_DEFUN([DOVECOT_WANT_UNWIND], [
  have_libunwind=no

  AS_IF([test "$want_libunwind" != "no"], [
    PKG_CHECK_MODULES([LIBUNWIND], [libunwind-generic], [have_libunwind=yes], [
      have_libunwind=no

      AS_IF([test "$want_libunwind" = "yes"], [
        AC_MSG_ERROR([cannot build with libuwind support: unwind library (libunwind-generic) not found])
      ])
    ])
  ])

  AS_IF([test "$have_libunwind" != "no"], [
    AC_DEFINE([HAVE_LIBUNWIND],, [Define this if you have libunwind])
  ])
])
