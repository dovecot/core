AC_DEFUN([DOVECOT_ARC4RANDOM], [
  AC_CHECK_FUNC([arc4random], [
    AC_DEFINE([HAVE_ARC4RANDOM], [1], [Define this if you arc4random()])
  ], [
      AC_CHECK_LIB([bsd], [arc4random], [
        LIBS="$LIBS -lbsd"
        AC_DEFINE([HAVE_ARC4RANDOM], [1], [Define this if you arc4random()])
        AC_DEFINE([HAVE_LIBBSD], [1], [Define this if you have libbsd])
      ])
  ])
])
