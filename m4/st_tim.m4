AC_DEFUN([DOVECOT_ST_TIM_TIMESPEC], [
  AC_CACHE_CHECK([if struct stat has st_?tim timespec fields],i_cv_have_st_tim_timespec,[
    AC_TRY_COMPILE([
      #include <sys/types.h>
      #include <sys/stat.h>
      #include <unistd.h>
    ], [
      struct stat st;
      unsigned long x = st.st_mtim.tv_nsec;
  
      return 0;
    ], [
      i_cv_have_st_tim_timespec=yes
    ], [
      i_cv_have_st_tim_timespec=no
    ])
  ])
  if test $i_cv_have_st_tim_timespec = yes; then
    AC_DEFINE(HAVE_STAT_XTIM,, [Define if you have st_?tim timespec fields in struct stat])
  fi

  AC_CACHE_CHECK([if struct stat has st_?timespec fields],i_cv_have_st_timespec,[
    AC_TRY_COMPILE([
      #include <sys/types.h>
      #include <sys/stat.h>
      #include <unistd.h>
    ], [
      struct stat st;
      unsigned long x = st.st_mtimespec.tv_nsec;
  
      return 0;
    ], [
      i_cv_have_st_timespec=yes
    ], [
      i_cv_have_st_timespec=no
    ])
  ])
  if test $i_cv_have_st_timespec = yes; then
    AC_DEFINE(HAVE_STAT_XTIMESPEC,, [Define if you have st_?timespec fields in struct stat])
  fi
]) 
