AC_DEFUN([DOVECOT_TYPEOF],[
  AC_CACHE_CHECK([for typeof],i_cv_have_typeof,[
    AC_TRY_COMPILE([
    ], [
      int foo;
      typeof(foo) bar;
    ], [
      i_cv_have_typeof=yes
    ], [
      i_cv_have_typeof=no
    ])
  ])
  if test $i_cv_have_typeof = yes; then
    AC_DEFINE(HAVE_TYPEOF,, [Define if you have typeof()])
  fi
])  
