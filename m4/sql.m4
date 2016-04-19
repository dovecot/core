AC_DEFUN([DOVECOT_SQL], [
  SQL_CFLAGS="$MYSQL_CFLAGS $PGSQL_CFLAGS $SQLITE_CFLAGS $CASSANDRA_CFLAGS"
  if test "$want_sql" != "plugin"; then
          SQL_LIBS="$MYSQL_LIBS $PGSQL_LIBS $SQLITE_LIBS $CASSANDRA_LIBS"
  else
          AC_DEFINE(SQL_DRIVER_PLUGINS,, [Build SQL drivers as plugins])
  fi
  sql_drivers=
  not_sql_drivers=
  
  if test "$found_sql_drivers" != "" || test "$want_sql" != "no"; then
          sql_drivers="$found_sql_drivers"
  
          AC_DEFINE(PASSDB_SQL,, [Build with SQL support])
          AC_DEFINE(USERDB_SQL,, [Build with SQL support])
          AUTH_LIBS="$AUTH_LIBS $SQL_LIBS"
          passdb="$passdb sql"
          userdb="$userdb sql"
  else
          not_passdb="$not_passdb sql"
          not_userdb="$not_userdb sql"
  fi
])
