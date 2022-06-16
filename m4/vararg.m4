AC_DEFUN([DOVECOT_VA_COPY], [
  AC_CACHE_CHECK([for an implementation of va_copy()],lib_cv_va_copy,[
          AC_RUN_IFELSE([AC_LANG_PROGRAM([[
          #include <stdarg.h>
          #include <stdlib.h>
          void f (int i, ...) {
          va_list args1, args2;
          va_start (args1, i);
          va_copy (args2, args1);
          if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            exit (1);
          va_end (args1); va_end (args2);
          }
          ]], [[
            f (0, 42);
            return 0;
          ]])],
          [lib_cv_va_copy=yes],
          [lib_cv_va_copy=no],[])
  ])
  AC_CACHE_CHECK([for an implementation of __va_copy()],lib_cv___va_copy,[
          AC_RUN_IFELSE([AC_LANG_PROGRAM([[
          #include <stdarg.h>
          #include <stdlib.h>
          void f (int i, ...) {
          va_list args1, args2;
          va_start (args1, i);
          __va_copy (args2, args1);
          if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            exit (1);
          va_end (args1); va_end (args2);
          }
          ]], [[
            f (0, 42);
            return 0;
          ]])],
          [lib_cv___va_copy=yes],
          [lib_cv___va_copy=no],[])
  ])
  
  AS_IF([test "$lib_cv_va_copy" = "yes"], [
    va_copy_func=va_copy
  ], [test "$lib_cv___va_copy" = "yes"], [
    va_copy_func=__va_copy
  ])
  
  AS_IF([test -n "$va_copy_func"], [
    AC_DEFINE_UNQUOTED(VA_COPY,$va_copy_func,[A 'va_copy' style function])
  ])
])
