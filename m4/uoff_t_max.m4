AC_DEFUN([DOVECOT_UOFF_T_MAX], [
  dnl * Do we have UOFF_T_MAX?
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <limits.h>
    #include <sys/types.h>
  ]], [[
    uoff_t i = UOFF_T_MAX;
  ]])],[
    :
  ],[
    AC_DEFINE_UNQUOTED(UOFF_T_MAX, $uofft_max, [Maximum value of uoff_t])
  ])
])
