AC_DEFUN([DOVECOT_WANT_ICU], [
  AS_IF([test "$want_icu" != "no"], [
    AS_IF([test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists icu-i18n 2>/dev/null], [
      PKG_CHECK_MODULES(LIBICU, icu-i18n)
      have_icu=yes
      AC_DEFINE(HAVE_LIBICU,, [Define if you want ICU normalization support for FTS])
    ], [test "$want_icu" = "yes"], [
      AC_MSG_ERROR(cannot build with libicu support: libicu-i18n not found)
    ])
  ])
  AM_CONDITIONAL(BUILD_LIBICU, test "$have_icu" = "yes")
])
