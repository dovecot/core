dnl * do we have struct iovec
AC_DEFUN([DOVECOT_IOVEC], [
  AC_CACHE_CHECK([for struct iovec], i_cv_struct_iovec,
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <sys/types.h>
  #include <sys/uio.h>
  #include <unistd.h>]],
  [[struct iovec *iovec;]])],
  [i_cv_struct_iovec=yes],
  [i_cv_struct_iovec=no])])

  AS_IF([test $i_cv_struct_iovec = yes], [
          AC_DEFINE(HAVE_STRUCT_IOVEC,, [Define if you have struct iovec])
  ])
])
