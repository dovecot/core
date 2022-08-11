AC_DEFUN([DOVECOT_WANT_MYSQL], [
  have_mysql=no
  have_mariadb=no

  dnl Check mysql driver to use:
  dnl - use mysqlclient library by default, this might be libmariadb in
  dnl   which case the library and headers are wrappers and can be used by
  dnl   the "incorrect" name of mysql,
  dnl - use libmariadb as a fallback and print a message that this
  dnl   alternative is used for transparency reasons,
  dnl - if neither can be found check manually, (which is currently necessary
  dnl   on CentOS7),
  dnl - if all else fails, print error and exit.
  mysql_driver=""
  AS_IF([test "$want_mysql" != "no"], [
    PKG_CHECK_MODULES([MYSQL], [mysqlclient], [have_mysql=yes], [have_mysql=no])

    AS_IF([test "$have_mysql" = "yes"], [
      mysql_driver="mysqlclient"
    ], [
      PKG_CHECK_MODULES([MARIADB], [libmariadb], [have_mariadb=yes], [have_mariadb=no])

      AS_IF([test "$have_mariadb" = "yes"], [
        AC_MSG_NOTICE([building MySQL support with MariaDB])

        have_mysql=yes
        mysql_driver="libmariadb"
        MYSQL_LIBS="$MARIADB_LIBS"
        MYSQL_CFLAGS="$MARIADB_CFLAGS"
      ])
    ])

    dnl Obsolete manual check for library/header location, currently
    dnl only necessary for CentOS7.
    dnl TODO: Make sure to remove this next block as soon as this is not
    dnl       officially supported anymore.
    dnl Based on code from PHP.
    AS_IF([test "$have_mysql" = "no"], [
      AC_MSG_CHECKING([for libmysqlclient library in expected file paths])

      AC_SUBST(MYSQL_CFLAGS)
      AC_SUBST(MYSQL_LIBS)
      for i in /usr /usr/local /usr/local/mysql; do
        for j in include include/mysql ""; do
          if test -r "$i/$j/mysql.h"; then
            MYSQL_INCLUDE="-I$i/$j"
          fi
        done
        for j in lib lib/mysql lib64 lib64/mysql ""; do
          if test -f "$i/$j/libmysqlclient.so" || test -f "$i/$j/libmysqlclient.a"; then
            MYSQL_LIBS="-L$i/$j -lmysqlclient"
          fi
        done
      done

      AS_IF([test "$MYSQL_INCLUDE" != "" && test "$MYSQL_LIBS" != ""], [
        AC_MSG_RESULT([using MYSQL_CFLAGS="$MYSQL_CFLAGS" and MYSQL_LIBS="$MYSQL_LIBS"])

        AC_CHECK_LIB(mysqlclient, mysql_init, [
          have_mysql=yes

          MYSQL_CFLAGS="$MYSQL_CFLAGS $MYSQL_INCLUDE"
        ],, $MYSQL_LIBS)
      ], [
        AC_MSG_RESULT([none found])
      ])
    ])

    AS_IF([test "$want_mysql" = "yes" && test "$have_mysql" = no], [
      AC_MSG_ERROR([cannot build with MySQL support: Neither MySQL (mysqlclient) nor MariaDB library (libmariadb) found])
    ])
  ])

  AS_IF([test "$have_mysql" != "no"], [
    found_sql_drivers="$found_sql_drivers mysql"
    AC_DEFINE(HAVE_MYSQL,, [Build with MySQL support])

    dnl $mysql_driver is set to "mysqlclient" or "libmariadb" if
    dnl "$have_mysql" is not "no"
    AC_CHECK_LIB($mysql_driver, mysql_ssl_set, [
      AC_DEFINE(HAVE_MYSQL_SSL,, [
        Define if your MySQL library has SSL functions
      ])
    ],, $MYSQL_LIBS)

    dnl add mysql-specific flags to the global CPPFLAGS to compile the
    dnl mysql-test programs
    tmp_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$MYSQL_CFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <mysql.h>
    ]], [[
      mysql_ssl_set(0, 0, 0, 0, 0, 0);
    ]])],[
      AC_DEFINE(HAVE_MYSQL_SSL_CIPHER,, [
        Define if your MySQL library supports setting cipher
      ])
    ])

    AC_COMPILE_IFELSE([_au_m4_changequote([,])AC_LANG_PROGRAM([[
      #include <mysql.h>
    ]], [[
      int i = MYSQL_OPT_SSL_VERIFY_SERVER_CERT;
    ]])], [
      AC_DEFINE(HAVE_MYSQL_SSL_VERIFY_SERVER_CERT,, [
        Define if your MySQL library supports verifying the name in the SSL certificate
      ])
    ])

    dnl restore CPPFLAGS for further build
    CPPFLAGS="$tmp_CPPFLAGS"
  ])
])
