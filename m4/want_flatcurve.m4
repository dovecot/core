AC_DEFUN([DOVECOT_WANT_FLATCURVE], [
  have_flatcurve=no
  AS_IF([test "$want_flatcurve" != "no"], [
    PKG_CHECK_MODULES(XAPIAN, xapian-core >= 1.4, [
      AC_DEFINE([HAVE_XAPIAN], 1, [Xapian is available])
      PKGCONFIG_REQUIRES="$PKGCONFIG_REQUIRES xapian-core"
      have_flatcurve=yes
      fts="$fts flatcurve"
    ],[
      AS_IF([test $want_flatcurve = yes], [
        AC_MSG_ERROR(cannot build with Flatcurve FTS: $XAPIAN_PKG_ERRORS)
      ])
    ])
  ])
  AM_CONDITIONAL(BUILD_FLATCURVE, test "$have_flatcurve" = "yes")
])
