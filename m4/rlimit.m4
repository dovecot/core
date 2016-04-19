dnl * Do we have RLIMIT_AS?
AC_DEFUN([DOVECOT_RLIMIT_AS], [
  AC_CACHE_CHECK([whether RLIMIT_AS exists],i_cv_have_rlimit_as,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <sys/time.h>
      #include <sys/resource.h>
    ]], [[
      struct rlimit r;
      getrlimit(RLIMIT_AS, &r);
    ]])],[
      i_cv_have_rlimit_as=yes
    ], [
      i_cv_have_rlimit_as=no
    ])
  ])
  
  if test $i_cv_have_rlimit_as = yes; then
    AC_DEFINE(HAVE_RLIMIT_AS,, [Define if you have RLIMIT_AS for setrlimit()])
  fi
])

dnl * Do we have RLIMIT_NPROC?
AC_DEFUN([DOVECOT_RLIMIT_NPROC], [
  AC_CACHE_CHECK([whether RLIMIT_NPROC exists],i_cv_have_rlimit_nproc,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <sys/time.h>
      #include <sys/resource.h>
    ]], [[
      struct rlimit r;
      getrlimit(RLIMIT_NPROC, &r);
    ]])],[
      i_cv_have_rlimit_nproc=yes
    ],[
      i_cv_have_rlimit_nproc=no
    ])
  ])
  
  if test $i_cv_have_rlimit_nproc = yes; then
    AC_DEFINE(HAVE_RLIMIT_NPROC,, [Define if you have RLIMIT_NPROC for setrlimit()])
  fi
])

dnl * Do we have RLIMIT_CORE?
AC_DEFUN([DOVECOT_RLIMIT_CORE], [
  AC_CACHE_CHECK([whether RLIMIT_CORE exists],i_cv_have_rlimit_core,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <sys/time.h>
      #include <sys/resource.h>
    ]], [[
      struct rlimit r;
      getrlimit(RLIMIT_CORE, &r);
    ]])],[
      i_cv_have_rlimit_core=yes
    ],[
      i_cv_have_rlimit_core=no
    ])
  ])
  
  if test $i_cv_have_rlimit_core = yes; then
    AC_DEFINE(HAVE_RLIMIT_CORE,, [Define if you have RLIMIT_CORE for getrlimit()])
  fi
])
