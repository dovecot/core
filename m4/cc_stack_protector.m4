dnl
dnl Check for support for -fstack-protector or -strong
dnl

AC_DEFUN([AC_CC_F_STACK_PROTECTOR],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    if test $disable_hardening = no; then
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-fstack-protector-strong], [
            CFLAGS="$CFLAGS -fstack-protector-strong"
            ],
            [
               gl_COMPILER_OPTION_IF([-fstack-protector], [
                 CFLAGS="$CFLAGS -fstack-protector"
                 ], [], [AC_LANG_PROGRAM([[
  #include <pthread.h>
  __thread unsigned int t_id;
              ]], [[t_id = 1;]])])
            ],
            [AC_LANG_PROGRAM([[
  #include <pthread.h>
  __thread unsigned int t_id;
              ]], [[t_id = 1;]])]
          )
      esac
    fi
])
