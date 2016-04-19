AC_DEFUN([DOVECOT_OFF_T_MAX], [
  dnl * Do we have OFF_T_MAX?
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <limits.h>
    #include <sys/types.h>
  ]], [[
    off_t i = OFF_T_MAX;
  ]])],[
    :
  ],[
    AC_DEFINE_UNQUOTED(OFF_T_MAX, $offt_max, [Maximum value of off_t])
  ])
])
