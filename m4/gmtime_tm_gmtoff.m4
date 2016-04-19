dnl * do we have tm_gmtoff
AC_DEFUN([DOVECOT_TM_GMTOFF], [
  AC_MSG_CHECKING([for tm_gmtoff])
  AC_CACHE_VAL(i_cv_field_tm_gmtoff,
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <time.h>]],
  [[struct tm *tm; return tm->tm_gmtoff;]])],
  [i_cv_field_tm_gmtoff=yes],
  [i_cv_field_tm_gmtoff=no])])
  if test $i_cv_field_tm_gmtoff = yes; then
          AC_DEFINE(HAVE_TM_GMTOFF,, [Define if you have struct tm->tm_gmtoff])
  fi
  AC_MSG_RESULT($i_cv_field_tm_gmtoff)
])
