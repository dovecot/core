AC_DEFUN([DOVECOT_DIRENT_DTYPE], [
  dnl * Do we have struct dirent->d_type
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <dirent.h>
  ]], [[
    struct dirent d;
    d.d_type = DT_DIR;
  ]])],[
    AC_DEFINE(HAVE_DIRENT_D_TYPE,, [Define if you have struct dirent->d_type])
  ],[])
])
