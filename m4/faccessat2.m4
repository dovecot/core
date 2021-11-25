AC_DEFUN([DOVECOT_FACCESSAT2], [
  dnl * Do we have the syscall faccessat2
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <asm/unistd.h>
  ]], [[
    int syscall = __NR_faccessat2;
  ]])],[
    AC_DEFINE(HAVE_FACCESSAT2,, [Define if we have syscall faccessat2])
  ],[])
])
