dnl
dnl Check for support for D_FORTIFY_SOURCE=2
dnl

AC_DEFUN([AC_CC_D_FORTIFY_SOURCE],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    if test $enable_hardening = yes; then
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2], [
            CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
            ],
            [],
            [AC_LANG_PROGRAM()]
          )
      esac
    fi
])
