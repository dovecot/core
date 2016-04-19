dnl * is dev_t an integer or something else?
AC_DEFUN([DOVECOT_TYPEOF_DEV_T], [
  AC_CACHE_CHECK([whether dev_t is struct],i_cv_dev_t_struct,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/types.h>
      struct test { dev_t a; };
      static struct test t = { 0 };
    ]],
    [[ ]])], [
      i_cv_dev_t_struct=no
    ],[
      i_cv_dev_t_struct=yes
    ])
  ])
  if test $i_cv_dev_t_struct = yes; then
    AC_DEFINE(DEV_T_STRUCT,, [Define if your dev_t is a structure instead of integer type])
  fi
]) 
