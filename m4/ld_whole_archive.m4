AC_DEFUN([AC_LD_WHOLE_ARCHIVE], [
    LD_WHOLE_ARCHIVE=
    LD_NO_WHOLE_ARCHIVE=
    AC_MSG_CHECKING([for linker option to include whole archive])
    ld_help="`$CC -Wl,-help 2>&1`"
    case "$ld_help" in
        *"--whole-archive"*)
            LD_WHOLE_ARCHIVE="--whole-archive"
            LD_NO_WHOLE_ARCHIVE="--no-whole-archive"
        ;;
    esac
    AS_IF([test "x$LD_WHOLE_ARCHIVE" != "x"],
      [AC_MSG_RESULT([-Wl,$LD_WHOLE_ARCHIVE])],
      [AC_MSG_RESULT([not supported])]
    )
    AC_SUBST([LD_WHOLE_ARCHIVE])
    AC_SUBST([LD_NO_WHOLE_ARCHIVE])
    AM_CONDITIONAL([HAVE_WHOLE_ARCHIVE], [test "x$LD_WHOLE_ARCHIVE" != "x"])
])
