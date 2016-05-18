AC_ARG_WITH(
  [libbsd],
  AS_HELP_STRING(
    [--with-libbsd],
    [Use libbsd (default is no)]
  ),
  [want_libbsd=yes],
  [want_libbsd=no]
)

AC_DEFUN([DOVECOT_ARC4RANDOM], [
  AC_ARG_WITH([libbsd], AS_HELP_STRING(
     [--with-libbsd],
     [Use libbsd (default is no)]
  ), [want_libbsd=$withval], [want_libbsd=no])
  AC_CHECK_FUNC([arc4random], AC_DEFINE([HAVE_ARC4RANDOM], [1], [Define this if you arc4random()]), [
      if test "$want_libbsd" = yes; then
        AC_CHECK_LIB([bsd], [arc4random], [
          LIBS="$LIBS -lbsd"
          AC_DEFINE([HAVE_ARC4RANDOM], [1], [Define this if you arc4random()])
          AC_DEFINE([HAVE_LIBBSD], [1], [Define this if you have libbsd])
        ])
      fi
  ])
])
