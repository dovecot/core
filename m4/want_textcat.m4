AC_DEFUN([DOVECOT_WANT_TEXTCAT], [
  if test $want_textcat != no; then
    if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists libexttextcat 2>/dev/null; then
      PKG_CHECK_MODULES(LIBEXTTEXTCAT, libexttextcat)
      TEXTCAT_DATADIR=`$PKG_CONFIG --variable=pkgdatadir libexttextcat`
      AC_DEFINE(HAVE_FTS_EXTTEXTCAT,, [Define if you want exttextcat support for FTS])
      have_fts_exttextcat=yes
      # Debian Wheezy workaround - LIBEXTTEXTCAT_CFLAGS include path is wrong:
      AC_CHECK_HEADERS(libexttextcat/textcat.h)
    else
      AC_CHECK_LIB(exttextcat, special_textcat_Init, [
        have_fts_exttextcat=yes
        AC_CHECK_HEADERS(libexttextcat/textcat.h)
        LIBEXTTEXTCAT_LIBS=-lexttextcat
        AC_DEFINE(HAVE_FTS_EXTTEXTCAT,, [Define if you want exttextcat support for FTS])
        TEXTCAT_DATADIR="/usr/share/libexttextcat"
        AC_SUBST(LIBEXTTEXTCAT_LIBS)
      ], [
        AC_CHECK_LIB(textcat, special_textcat_Init, [
          have_fts_textcat=yes
          TEXTCAT_DATADIR="/usr/share/libtextcat"
          AC_CHECK_HEADERS(libtextcat/textcat.h)
        ])
      ])
      if test $want_textcat = yes && test "$have_fts_exttextcat" != yes && test "$have_fts_textcat" != yes; then
        AC_ERROR([Can't build with textcat support: libtextcat or libexttextcat not found])
      fi
    fi
    if test "$have_fts_exttextcat" = yes || test "$have_fts_textcat" = yes; then
      AC_DEFINE(HAVE_FTS_TEXTCAT,, [Define if you want textcat support for FTS])
      AC_DEFINE_UNQUOTED(TEXTCAT_DATADIR, "$TEXTCAT_DATADIR", [Points to textcat pkgdatadir containing the language files])
    fi
  fi
  AM_CONDITIONAL(BUILD_FTS_TEXTCAT, test "$have_fts_textcat" = "yes")
  AM_CONDITIONAL(BUILD_FTS_EXTTEXTCAT, test "$have_fts_exttextcat" = "yes")
])
