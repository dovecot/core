AC_DEFUN([DOVECOT_WANT_APPARMOR], [
  want_apparmor=auto
  AC_ARG_WITH([apparmor],
     [AS_HELP_STRING([--with-apparmor], [enable apparmor plugin (default=auto)])],
     [want_apparmor=$withval])

  have_apparmor=no
  if test $want_apparmor != no; then
    AC_CHECK_HEADER([sys/apparmor.h], [
      AC_CHECK_LIB([apparmor], [aa_change_hat], [
        have_apparmor=yes
        AC_SUBST([APPARMOR_LIBS], [-lapparmor])
      ])
    ])
  fi

  if test $want_apparmor = yes; then
    if test $have_apparmor = no; then
      AC_MSG_FAILURE([apparmor was not found])
    fi
  fi

  AM_CONDITIONAL(HAVE_APPARMOR, test "$have_apparmor" = "yes")
])
