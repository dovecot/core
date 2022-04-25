AC_DEFUN([DOVECOT_WANT_STEMMER], [
  AS_IF([test "$want_stemmer" != "no"], [
    AC_CHECK_LIB(stemmer, sb_stemmer_new, [
      have_fts_stemmer=yes
      AC_DEFINE(HAVE_FTS_STEMMER,, [Define if you want stemming support for FTS])
    ], [
      AS_IF([test "$want_stemmer" = "yes"], [
        AC_MSG_ERROR(cannot build with stemmer support: libstemmer not found)
      ])
    ])
  ])

  AM_CONDITIONAL([BUILD_FTS_STEMMER], [test "$have_fts_stemmer" = "yes"])
])
