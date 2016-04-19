AC_DEFUN([DOVECOT_WANT_SQLITE], [
  if test $want_sqlite != no; then
          AC_CHECK_LIB(sqlite3, sqlite3_open, [
                  AC_CHECK_HEADER(sqlite3.h, [
                          SQLITE_LIBS="$SQLITE_LIBS -lsqlite3"
  
                          AC_DEFINE(HAVE_SQLITE,, [Build with SQLite3 support])
                          found_sql_drivers="$found_sql_drivers sqlite"
                  ], [
                    if test $want_sqlite = yes; then
                      AC_ERROR([Can't build with SQLite support: sqlite3.h not found])
                    fi
                  ])
          ], [
            if test $want_sqlite = yes; then
              AC_ERROR([Can't build with SQLite support: libsqlite3 not found])
            fi
          ])
  fi
])
