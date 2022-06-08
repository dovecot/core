AC_DEFUN([DOVECOT_WANT_SOLR], [
  have_expat=no
  have_solr=no

  AS_IF([test "$want_solr" != "no"], [
    PKG_CHECK_MODULES([EXPAT], [expat], [have_expat=yes], [
      have_expat=no

      AS_IF([test "$want_solr" = "yes"], [
        AC_MSG_ERROR([cannot build with Solr support: expat library not found])
      ])
    ])
  ])

  AS_IF([test "$have_expat" != "no"], [
    have_solr=yes
    fts="$fts solr"
  ])

  AM_CONDITIONAL(BUILD_SOLR, test "$have_solr" = "yes")
])
