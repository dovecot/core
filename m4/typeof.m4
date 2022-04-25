AC_DEFUN([DOVECOT_TYPEOF],[
  AC_CACHE_CHECK([for typeof],i_cv_have_typeof,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    ]], [[
      int foo;
      typeof(foo) bar;
    ]])],[
      i_cv_have_typeof=yes
    ], [
      i_cv_have_typeof=no
    ])
  ])
  AS_IF([test $i_cv_have_typeof = yes], [
    AC_DEFINE(HAVE_TYPEOF,, [Define if you have typeof()])
  ])
])
