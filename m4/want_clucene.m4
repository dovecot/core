AC_DEFUN([DOVECOT_WANT_CLUCENE], [
  have_lucene=no
  if test "$want_lucene" = "yes"; then
    PKG_CHECK_MODULES(CLUCENE, libclucene-core,, [
      # no pkg-config file for clucene. fallback to defaults.
      # FIXME: we should verify here that this actually works..
      CLUCENE_LIBS="-lclucene-shared -lclucene-core"
    ])
    have_lucene=yes
    fts="$fts lucene"
  fi
])
