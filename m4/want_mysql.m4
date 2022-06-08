AC_DEFUN([DOVECOT_WANT_MYSQL], [
  have_mysql=no
  have_mariadb=no

  dnl Check mysql driver to use:
  dnl - use mysqlclient library by default, fall back to mariadb (in which
  dnl   case print a message that mariadb is used),
  dnl - if neither can be found print error.
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

    ssl_define=""
    AS_IF([test "$have_openssl" = "yes"], [
      ssl_define="#define HAVE_OPENSSL"
    ])

    dnl add mysql-specific flags to the global CPPFLAGS to compile the
    dnl mysql-test programs
    tmp_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$MYSQL_CFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      $ssl_define
      #include <mysql.h>
    ]], [[
      mysql_ssl_set(0, 0, 0, 0, 0, 0);
    ]])],[
      AC_DEFINE(HAVE_MYSQL_SSL_CIPHER,, [
        Define if your MySQL library supports setting cipher
      ])
    ])

    AC_COMPILE_IFELSE([_au_m4_changequote([,])AC_LANG_PROGRAM([[
      $ssl_define
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
