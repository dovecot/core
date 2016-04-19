AC_DEFUN([AC_CHECKTYPE2], [
  AC_MSG_CHECKING([for $1])
  AC_CACHE_VAL(i_cv_type_$1,
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <sys/types.h>
  $2]], [[$1 t;]])],[i_cv_type_$1=yes],[i_cv_type_$1=no])])
  AC_MSG_RESULT($i_cv_type_$1)
])
