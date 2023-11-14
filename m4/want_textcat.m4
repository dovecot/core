AC_DEFUN([DOVECOT_WANT_TEXTCAT], [
  AS_IF([test "$want_textcat" != "no"], [
    AS_IF([test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists libexttextcat 2>/dev/null], [
      PKG_CHECK_MODULES(LIBEXTTEXTCAT, libexttextcat)
      TEXTCAT_DATADIR=`$PKG_CONFIG --variable=pkgdatadir libexttextcat`
      AC_DEFINE(HAVE_LANG_EXTTEXTCAT,, [Define if you want exttextcat support for lib-language])
      have_lang_exttextcat=yes

      dnl Debian Wheezy workaround - LIBEXTTEXTCAT_CFLAGS include path is wrong:
      AC_CHECK_HEADERS(libexttextcat/textcat.h)
    ], [
      AC_CHECK_LIB(exttextcat, special_textcat_Init, [
        have_lang_exttextcat=yes
        AC_CHECK_HEADERS(libexttextcat/textcat.h)
        LIBEXTTEXTCAT_LIBS=-lexttextcat
        AC_DEFINE(HAVE_LANG_EXTTEXTCAT,, [Define if you want exttextcat support for lib-language])
        TEXTCAT_DATADIR="/usr/share/libexttextcat"
        AC_SUBST(LIBEXTTEXTCAT_LIBS)
      ], [
        AC_CHECK_LIB(textcat, special_textcat_Init, [
          have_lang_textcat=yes
          TEXTCAT_DATADIR="/usr/share/libtextcat"
          AC_CHECK_HEADERS(libtextcat/textcat.h)
        ])
      ])
      AS_IF([test "$want_textcat" = "yes" && test "$have_lang_exttextcat" != "yes" && test "$have_lang_textcat" != "yes"], [
        AC_MSG_ERROR(cannot build with textcat support: libtextcat or libexttextcat not found)
      ])
    ])
    AS_IF([test "$have_lang_exttextcat" = "yes" || test "$have_lang_textcat" = "yes"], [
      AC_DEFINE(HAVE_LANG_TEXTCAT,, [Define if you want textcat support for lib-language])
      AC_DEFINE_UNQUOTED(TEXTCAT_DATADIR, "$TEXTCAT_DATADIR", [Points to textcat pkgdatadir containing the language files])
    ])
  ])
  AM_CONDITIONAL(BUILD_LANG_TEXTCAT, test "$have_lang_textcat" = "yes")
  AM_CONDITIONAL(BUILD_LANG_EXTTEXTCAT, test "$have_lang_exttextcat" = "yes")
])
