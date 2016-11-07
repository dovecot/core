AC_DEFUN([DOVECOT_UNSETENV_RET_INT], [
  AC_CACHE_CHECK([if unsetenv returns int],i_cv_unsetenv_ret_int,[
    AC_TRY_COMPILE([
      #include <stdlib.h>
    ], [
      if (unsetenv("env") < 0) { }
    ], [
      i_cv_unsetenv_ret_int=yes
    ], [
      i_cv_unsetenv_ret_int=no
    ])
  ])
  if test $i_cv_unsetenv_ret_int = yes; then
    AC_DEFINE(UNSETENV_RET_INT,, [Define if unsetenv() returns int])
  fi
])
