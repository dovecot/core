AC_DEFUN([DOVECOT_WANT_PGSQL], [
  have_pgsql=no

  AS_IF([test "$want_pgsql" != "no"], [
    PKG_CHECK_MODULES([PGSQL], [libpq], [have_pgsql=yes], [
      have_pgsql=no

      AS_IF([test "$want_pgsql" = "yes"], [
        AC_MSG_ERROR([cannot build with PostgreSQL support: PostgreSQL library (libpq) not found])
      ])
    ])
  ])

  AS_IF([test "$have_pgsql" != "no"], [
    found_sql_drivers="$found_sql_drivers pgsql"

    AC_CHECK_LIB(pq, PQescapeStringConn, [
      AC_DEFINE(HAVE_PQESCAPE_STRING_CONN,, [
        Define if libpq has PQescapeStringConn function
      ])
    ],, $PGSQL_LIBS)

    AC_DEFINE(HAVE_PGSQL,, [Build with PostgreSQL support])
  ])
])
