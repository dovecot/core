dnl
dnl Check for support for -fstack-protector or -strong
dnl

AC_DEFUN([AC_CC_F_STACK_PROTECTOR],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    if test $enable_hardening = yes; then
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-fstack-protector-strong], [
            CFLAGS="$CFLAGS -fstack-protector-strong"
            ],
            [
               gl_COMPILER_OPTION_IF([-fstack-protector], [
                 CFLAGS="$CFLAGS -fstack-protector"
                 ], [], [AC_LANG_PROGRAM()])
            ],
            [AC_LANG_PROGRAM()]
          )
      esac
    fi
])
