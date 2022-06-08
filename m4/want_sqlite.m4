AC_DEFUN([DOVECOT_WANT_SQLITE], [
  have_sqlite=no

  AS_IF([test "$want_sqlite" != "no"], [
    PKG_CHECK_MODULES([SQLITE], [sqlite3], [have_sqlite=yes], [
      have_sqlite=no

      AS_IF([test "$want_sqlite" = "yes"], [
        AC_MSG_ERROR([cannot build with SQLite support: sqlite3 library not found])
      ])
    ])
  ])

  AS_IF([test "$have_sqlite" != "no"], [
    found_sql_drivers="$found_sql_drivers sqlite"
    AC_DEFINE(HAVE_SQLITE,, [Build with SQLite3 support])
  ])
])
