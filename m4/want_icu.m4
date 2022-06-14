AC_DEFUN([DOVECOT_WANT_ICU], [
  have_icu=no

  AS_IF([test "$want_icu" != "no"], [
    PKG_CHECK_MODULES([LIBICU], [icu-i18n], [have_icu=yes], [
      have_icu=no

      AS_IF([test "$want_icu" = "yes"], [
        AC_MSG_ERROR(cannot build with icu support: icu library (icu-i18n) not found)
      ])
    ])
  ])

  AS_IF([test "$have_icu" != "no"], [
    AC_DEFINE(HAVE_LIBICU,, [Define if you want ICU normalization support for FTS])
  ])

  AM_CONDITIONAL(BUILD_LIBICU, test "$have_icu" = "yes")
])
