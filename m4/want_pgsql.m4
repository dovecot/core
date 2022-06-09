AC_DEFUN([DOVECOT_WANT_PGSQL], [
  have_pgsql=no

  AS_IF([test "$want_pgsql" != "no"], [
    PKG_CHECK_MODULES([PGSQL], [libpq], [have_pgsql=yes], [have_pgsql=no])

    dnl Obsolete manual check for library/header location, currently
    dnl only necessary for CentOS7.
    dnl TODO: Make sure to remove this next block as soon as this is not
    dnl       officially supported anymore
    dnl Based on code from PHP.
    AS_IF([test "$have_pgsql" = "no"], [
      AC_MSG_CHECKING([for libpq library in expected file paths])

      AC_SUBST(PGSQL_CFLAGS)
      AC_SUBST(PGSQL_LIBS)
      for i in /usr /usr/local /usr/local/pgsql; do
        for j in include include/pgsql include/postgres include/postgresql ""; do
          if test -r "$i/$j/libpq-fe.h"; then
            PGSQL_INCLUDE="-I$i/$j"
          fi
        done
        for lib in lib lib64; do
          for j in $lib $lib/pgsql $lib/postgres $lib/postgresql ""; do
            if test -f "$i/$lib/$j/libpq.so" || test -f "$i/$lib/$j/libpq.a"; then
              PGSQL_LIBS="-L$i/$lib/$j -lpq"
            fi
          done
        done
      done

      AS_IF([test "$PGSQL_INCLUDE" != "" || test "$PGSQL_LIBS" != ""], [
        AC_MSG_RESULT([using PGSQL_CFLAGS="$PGSQL_CFLAGS" and PGSQL_LIBS="$PGSQL_LIBS"])

        AC_CHECK_LIB(pq, PQconnectdb, [
          have_pgsql=yes
          PGSQL_CFLAGS="$PGSQL_CFLAGS $PGSQL_INCLUDE"
        ],, $PGSQL_LIBS)
      ], [
        AC_MSG_RESULT([none found])
      ])
    ])

    AS_IF([test "$want_pgsql" = "yes" && test "$have_pgsql" = "no"], [
      AC_MSG_ERROR([cannot build with PostgreSQL support: PostgreSQL library (libpq) not found])
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
