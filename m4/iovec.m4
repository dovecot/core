dnl * do we have struct iovec
AC_DEFUN([DOVECOT_IOVEC], [
  AC_MSG_CHECKING([for struct iovec])
  AC_CACHE_VAL(i_cv_struct_iovec,
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <sys/types.h>
  #include <sys/uio.h>
  #include <unistd.h>]],
  [[struct iovec *iovec;]])],
  [i_cv_struct_iovec=yes],
  [i_cv_struct_iovec=no])])
  
  if test $i_cv_struct_iovec = yes; then
          AC_DEFINE(HAVE_STRUCT_IOVEC,, [Define if you have struct iovec])
  fi
  AC_MSG_RESULT($i_cv_struct_iovec) 
])
