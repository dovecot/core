AC_DEFUN([DOVECOT_TIME_T_SIGNED], [
  AC_CACHE_CHECK([whether time_t is signed],i_cv_signed_time_t,[
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <sys/types.h>
      #include <stdlib.h>
      int main() {
        /* return 0 if we're signed */
        exit((time_t)(int)-1 <= 0 ? 0 : 1);
      }
    ]])],[
      i_cv_signed_time_t=yes
    ], [
      i_cv_signed_time_t=no
    ])
  ])
  if test $i_cv_signed_time_t = yes; then
    AC_DEFINE(TIME_T_SIGNED,, [Define if your time_t is signed])
  fi
])
