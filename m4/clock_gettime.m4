AC_DEFUN([DOVECOT_CLOCK_GETTIME], [
  AC_SEARCH_LIBS(clock_gettime, rt, [
    AC_DEFINE(HAVE_CLOCK_GETTIME,, [Define if you have the clock_gettime function])
  ])
])
