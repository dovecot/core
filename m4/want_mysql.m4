AC_DEFUN([DOVECOT_WANT_MYSQL], [
  have_mysql=no

  AS_IF([test "$want_mysql" != "no"], [
    PKG_CHECK_MODULES([MYSQL], [mysqlclient], [have_mysql=yes], [
      have_mysql=no

      AS_IF([test "$want_mysql" = "yes"], [
        AC_MSG_ERROR([cannot build with MySQL support: MySQL library (mysqlclient) not found])
      ])
    ])
  ])

  AS_IF([test "$have_mysql" != "no"], [
    found_sql_drivers="$found_sql_drivers mysql"
    AC_DEFINE(HAVE_MYSQL,, [Build with MySQL support])

    AC_CHECK_LIB(mysqlclient, mysql_ssl_set, [
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
