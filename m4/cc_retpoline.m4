dnl
dnl Check for support for Retpoline
dnl

AC_DEFUN([AC_CC_RETPOLINE],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    if test $enable_hardening = yes; then
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-mfunction-return=thunk -mindirect-branch=thunk], [
            CFLAGS="$CFLAGS -mfunction-return=thunk -mindirect-branch=thunk"
            ],
            [],
            [AC_LANG_PROGRAM([[
  #include <pthread.h>
  __thread unsigned int t_id;
              ]], [[t_id = 1;]])]
          )
      esac
    fi
])
