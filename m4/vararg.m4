AC_DEFUN([DOVECOT_VA_COPY], [
  AC_CACHE_CHECK([for an implementation of va_copy()],lib_cv_va_copy,[
          AC_RUN_IFELSE([AC_LANG_SOURCE([[
          #include <stdarg.h>
          void f (int i, ...) {
          va_list args1, args2;
          va_start (args1, i);
          va_copy (args2, args1);
          if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            exit (1);
          va_end (args1); va_end (args2);
          }
          int main() {
            f (0, 42);
            return 0;
          }]])],
          [lib_cv_va_copy=yes],
          [lib_cv_va_copy=no],[])
  ])
  AC_CACHE_CHECK([for an implementation of __va_copy()],lib_cv___va_copy,[
          AC_RUN_IFELSE([AC_LANG_SOURCE([[
          #include <stdarg.h>
          void f (int i, ...) {
          va_list args1, args2;
          va_start (args1, i);
          __va_copy (args2, args1);
          if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            exit (1);
          va_end (args1); va_end (args2);
          }
          int main() {
            f (0, 42);
            return 0;
          }]])],
          [lib_cv___va_copy=yes],
          [lib_cv___va_copy=no],[])
  ])
  
  if test "x$lib_cv_va_copy" = "xyes"; then
    va_copy_func=va_copy
  else if test "x$lib_cv___va_copy" = "xyes"; then
    va_copy_func=__va_copy
  fi
  fi
  
  if test -n "$va_copy_func"; then
    AC_DEFINE_UNQUOTED(VA_COPY,$va_copy_func,[A 'va_copy' style function])
  fi
])

AC_DEFUN([DOVECOT_VA_COPY_BYVAL], [
  AC_CACHE_CHECK([whether va_lists can be copied by value],lib_cv_va_val_copy,[
          AC_RUN_IFELSE([AC_LANG_SOURCE([[
          #include <stdarg.h>
          void f (int i, ...) {
          va_list args1, args2;
          va_start (args1, i);
          args2 = args1;
          if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            exit (1);
          va_end (args1); va_end (args2);
          }
          int main() {
            f (0, 42);
            return 0;
          }]])],
          [lib_cv_va_val_copy=yes],
          [lib_cv_va_val_copy=no],[])
  ])
  
  if test "x$lib_cv_va_val_copy" = "xno"; then
    AC_DEFINE(VA_COPY_AS_ARRAY,1, ['va_lists' cannot be copies as values])
  fi
])
