dnl ***
dnl *** C99 vsnprintf()?
dnl ***

AC_DEFUN([DOVECOT_C99_VSNPRINTF], [
  AC_CACHE_CHECK([for C99 vsnprintf()],i_cv_c99_vsnprintf,[
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
    #include <stdio.h>
    #include <stdarg.h>
    static int f(const char *fmt, ...) {
      va_list args;
      char buf[13];
      int ret;
  
      va_start(args, fmt);
      ret = vsnprintf(buf, 11, fmt, args) != 12 || buf[11-1] != '\0';
      va_end(args);
      return ret;
    }
    int main() {
      return f("hello %s%d", "world", 1);
    }]])],
    [i_cv_c99_vsnprintf=yes],
    [i_cv_c99_vsnprintf=no])
  ])
  if test $i_cv_c99_vsnprintf = no; then
    AC_DEFINE(HAVE_OLD_VSNPRINTF,, [Define if you don't have C99 compatible vsnprintf() call])
  fi
])
