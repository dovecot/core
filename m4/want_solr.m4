AC_DEFUN([DOVECOT_WANT_SOLR], [
  have_solr=no
  if test "$want_solr" != "no"; then
    dnl need libexpat
    AC_CHECK_LIB(expat, XML_Parse, [
      AC_CHECK_HEADER(expat.h, [
        have_solr=yes
        fts="$fts solr"
      ], [
        if test $want_solr = yes; then
          AC_ERROR([Can't build with Solr support: expat.h not found])
        fi
      ])
    ], [
      if test $want_solr = yes; then
        AC_ERROR([Can't build with Solr support: libexpat not found])
      fi
    ])
  fi
  AM_CONDITIONAL(BUILD_SOLR, test "$have_solr" = "yes")
])
