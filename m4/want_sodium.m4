AC_DEFUN([DOVECOT_WANT_SODIUM], [
  if test "$want_sodium" != "no"; then
    if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists libsodium 2>/dev/null; then
      PKG_CHECK_MODULES(LIBSODIUM, libsodium)
      have_sodium=yes
      AC_DEFINE(HAVE_LIBSODIUM,, [Define if you have libsodium])
    elif test "$want_sodium" = "yes"; then
      AC_ERROR([Can't build with libsodium: not found])
    fi
  fi
  AM_CONDITIONAL(BUILD_LIBSODIUM, test "$have_sodium" = "yes")
])
