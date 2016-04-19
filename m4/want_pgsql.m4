AC_DEFUN([DOVECOT_WANT_PGSQL], [
  if test $want_pgsql != no; then
    AC_CHECK_PROG(PG_CONFIG, pg_config, pg_config, NO)
    if test $PG_CONFIG = NO; then
      # based on code from PHP
      for i in /usr /usr/local /usr/local/pgsql; do
        for j in include include/pgsql include/postgres include/postgresql ""; do
  	if test -r "$i/$j/libpq-fe.h"; then
  	  PGSQL_INCLUDE=$i/$j
  	fi
        done
        for lib in lib lib64; do
  	for j in $lib $lib/pgsql $lib/postgres $lib/postgresql ""; do
  	  if test -f "$i/$j/libpq.so" || test -f "$i/$j/libpq.a"; then
  	    PGSQL_LIBDIR=$i/$j
  	  fi
  	done
        done
      done
    else
      PGSQL_INCLUDE="`$PG_CONFIG --includedir`"
      PGSQL_LIBDIR="`$PG_CONFIG --libdir`"  
    fi
  
    old_LIBS=$LIBS
    if test "$PGSQL_LIBDIR" != ""; then
      LIBS="$LIBS -L$PGSQL_LIBDIR"
    fi
  
    AC_CHECK_LIB(pq, PQconnectdb, [
  	  AC_CHECK_LIB(pq, PQescapeStringConn, [
  		  AC_DEFINE(HAVE_PQESCAPE_STRING_CONN,, [Define if libpq has PQescapeStringConn function])
  	  ])
  	  old_CPPFLAGS=$CPPFLAGS
  	  if test "$PGSQL_INCLUDE" != ""; then
  		  CPPFLAGS="$CPPFLAGS -I$PGSQL_INCLUDE"
  	  fi
  	  AC_CHECK_HEADER(libpq-fe.h, [
  		  if test "$PGSQL_INCLUDE" != ""; then
  			  PGSQL_CFLAGS="$PGSQL_CFLAGS -I$PGSQL_INCLUDE"
  		  fi
  		  if test "$PGSQL_LIBDIR" != ""; then
  			  PGSQL_LIBS="$PGSQL_LIBS -L$PGSQL_LIBDIR"
  		  fi
  		  PGSQL_LIBS="$PGSQL_LIBS -lpq"
  		  AC_DEFINE(HAVE_PGSQL,, [Build with PostgreSQL support])
  		  found_sql_drivers="$found_sql_drivers pgsql"
  	  ], [
  	    if test $want_pgsql = yes; then
  	      AC_ERROR([Can't build with PostgreSQL support: libpq-fe.h not found])
  	    fi
  	  ])
  	  CPPFLAGS=$old_CPPFLAGS
    ], [
      if test $want_pgsql = yes; then
        AC_ERROR([Can't build with PostgreSQL support: libpq not found])
      fi
    ])
    LIBS=$old_LIBS
  fi
])
