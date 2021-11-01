AC_DEFUN([DOVECOT_WANT_FLATCURVE], [
  have_flatcurve=no
  AS_IF([test "$want_flatcurve" != "no"], [
    PKG_CHECK_MODULES(XAPIAN, xapian-core >= 1.2, [
      AC_DEFINE([HAVE_XAPIAN], 1, [Xapian is available])
      PKGCONFIG_REQUIRES="$PKGCONFIG_REQUIRES xapian-core"
      have_flatcurve=yes
      fts="$fts flatcurve"
      PKG_CHECK_MODULES(XAPIAN, xapian-core >= 1.4, [
        AC_DEFINE([XAPIAN_HAS_COMPACT],1,[Xapian compaction support (1.4+)])
      ])
    ],[
      AS_IF([test $want_flatcurve = yes], [
        AC_ERROR([Can't build with Flatcurve FTS: $XAPIAN_PKG_ERRORS])
      ])
    ])
  ])
  AM_CONDITIONAL(BUILD_FLATCURVE, test "$have_flatcurve" = "yes")
])
