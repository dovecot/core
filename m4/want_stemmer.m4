AC_DEFUN([DOVECOT_WANT_STEMMER], [
  if test $want_stemmer != no; then
    AC_CHECK_LIB(stemmer, sb_stemmer_new, [
      have_fts_stemmer=yes
      AC_DEFINE(HAVE_FTS_STEMMER,, [Define if you want stemming support for FTS])
    ], [
      if test $want_stemmer = yes; then
        AC_ERROR([Can't build with stemmer support: libstemmer not found])
      fi
    ])
  fi

  AM_CONDITIONAL([BUILD_FTS_STEMMER], [test "$have_fts_stemmer" = "yes"])
])
