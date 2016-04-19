AC_DEFUN([DOVECOT_WANT_ICU], [
  if test "$want_icu" != "no"; then
    if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists icu-i18n 2>/dev/null; then
      PKG_CHECK_MODULES(LIBICU, icu-i18n)
      have_icu=yes
      AC_DEFINE(HAVE_LIBICU,, [Define if you want ICU normalization support for FTS])
    elif test "$want_icu" = "yes"; then
      AC_ERROR([Can't build with libicu support: libicu-i18n not found])
    fi
  fi
  AM_CONDITIONAL(BUILD_LIBICU, test "$have_icu" = "yes")
])
