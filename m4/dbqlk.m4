dnl * Check if we have struct dqblk.dqb_curblocks
AC_DEFUN([DOVECOT_DQBLK_CURBLOCKS], [
  AC_CACHE_CHECK([if struct dqblk.dqb_curblocks exists],i_cv_have_dqblk_dqb_curblocks,[
    AC_TRY_COMPILE([
      #include <sys/types.h>
      #include "$srcdir/src/plugins/quota/quota-fs.h"
    ], [
      struct dqblk dqblk;
      unsigned int x = dqblk.dqb_curblocks;
    ], [
      i_cv_have_dqblk_dqb_curblocks=yes
    ], [
      i_cv_have_dqblk_dqb_curblocks=no
    ])
  ])
  if test $i_cv_have_dqblk_dqb_curblocks = yes; then
    AC_DEFINE(HAVE_STRUCT_DQBLK_CURBLOCKS,, [Define if struct sqblk.dqb_curblocks exists])
  fi
])

dnl * Check if we have struct dqblk.dqb_curspace
AC_DEFUN([DOVECOT_DQBLK_CURSPACE], [
  AC_CACHE_CHECK([if struct dqblk.dqb_curspace exists],i_cv_have_dqblk_dqb_curspace,[
    AC_TRY_COMPILE([
      #include <sys/types.h>
      #include "$srcdir/src/plugins/quota/quota-fs.h"
    ], [
      struct dqblk dqblk;
      unsigned int x = dqblk.dqb_curspace;
    ], [
      i_cv_have_dqblk_dqb_curspace=yes
    ], [
      i_cv_have_dqblk_dqb_curspace=no
    ])
  ])
  if test $i_cv_have_dqblk_dqb_curspace = yes; then
    AC_DEFINE(HAVE_STRUCT_DQBLK_CURSPACE,, [Define if struct sqblk.dqb_curspace exists])
  fi
])
