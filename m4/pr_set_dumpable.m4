AC_DEFUN([DOVECOT_PR_SET_DUMPABLE], [
  AC_CACHE_CHECK([whether PR_SET_DUMPABLE exists],i_cv_have_pr_set_dumpable,[
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/prctl.h>
    ]], [[
      prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    ]])],[
      i_cv_have_pr_set_dumpable=yes
    ], [
      i_cv_have_pr_set_dumpable=no
    ])
  ])
  AS_IF([test $i_cv_have_pr_set_dumpable = yes], [
    AC_DEFINE(HAVE_PR_SET_DUMPABLE,, [Define if you have prctl(PR_SET_DUMPABLE)])
  ])
])
