dnl * Check if we have Q_QUOTACTL ioctl (Solaris)
AC_DEFUN([DOVECOT_Q_QUOTACTL], [
  AC_CACHE_CHECK([if Q_QUOTACTL ioctl exists],i_cv_have_ioctl_q_quotactl,[
    AC_TRY_COMPILE([
      #include <sys/types.h>
      #include <sys/fs/ufs_quota.h>
    ], [
      struct quotctl ctl;
      ioctl(0, Q_QUOTACTL, &ctl);
    ], [
      i_cv_have_ioctl_q_quotactl=yes
    ], [
      i_cv_have_ioctl_q_quotactl=no
    ])
  ])
  
  if test $i_cv_have_ioctl_q_quotactl = yes; then
    AC_DEFINE(HAVE_Q_QUOTACTL,, [Define if Q_QUOTACTL exists])
  fi
])
