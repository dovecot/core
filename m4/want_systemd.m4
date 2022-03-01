dnl Checks for libsystemd existence and where
dnl to put systemd unit files. You can have
dnl systemd units without libsystemd.

AC_DEFUN([DOVECOT_WANT_SYSTEMD], [
  systemdservicetype='simple'
  have_libsystemd=no

  AS_IF([test "$want_systemd" != "no"], [
    dnl Check for actual systemd integration
    PKG_CHECK_MODULES([SYSTEMD], [libsystemd], [
      AC_DEFINE([HAVE_LIBSYSTEMD],[1], [Define to 1 if you have libsystemd])
      systemdservicetype='notify'
      have_libsystemd=yes
    ], AS_IF([test "$want_systemd" = "yes"], [
         AC_MSG_WARN([libsystemd not found - full integration disabled])
       ])
    )
    dnl Check for unit file installation
    AC_MSG_CHECKING([for systemd unit directory])
    AS_IF([test "$systemdsystemunitdir" = ""], [
       PKG_CHECK_VAR([systemdsystemunitdir], [systemd], [systemdsystemunitdir])
    ])
    AC_MSG_RESULT([$systemdsystemunitdir])
    AS_IF([test "$systemdsystemunitdir" = ""], [
      AS_IF([test "$want_systemd" = "yes"], [
        AC_MSG_ERROR([Cannot determine where to put systemd files - Provide systemdsystemunitdir manually])
      ])
      dnl Cannot enable even unit file installation.
      want_systemd=no
    ])
  ])
  AC_SUBST(systemdsystemunitdir)
  AC_SUBST(systemdservicetype)
  AM_CONDITIONAL(WANT_SYSTEMD, [test "$want_systemd" != "no"])
])
