AC_DEFUN([DOVECOT_WANT_MYSQL], [
  have_mysql=no
  if test $want_mysql != no; then
    AC_CHECK_PROG(MYSQL_CONFIG, mysql_config, mysql_config, NO)
    if test $MYSQL_CONFIG = NO; then
  	# based on code from PHP
  	MYSQL_LIBS="-lmysqlclient -lz -lm"
  	for i in /usr /usr/local /usr/local/mysql; do
  		for j in include include/mysql ""; do
  			if test -r "$i/$j/mysql.h"; then
  				MYSQL_INCLUDE="-I$i/$j"
  			fi
  		done
  		for j in lib lib/mysql lib64 lib64/mysql ""; do
  			if test -f "$i/$j/libmysqlclient.so" || test -f "$i/$j/libmysqlclient.a"; then
  				MYSQL_LIBS="-L$i/$j -lmysqlclient -lz -lm"
  			fi
  		done
  	done
    else
      MYSQL_INCLUDE="`$MYSQL_CONFIG --include`"
      MYSQL_LIBS="`$MYSQL_CONFIG --libs`"
    fi
  
    old_LIBS=$LIBS
    if test "$MYSQL_LIBS" != ""; then
      LIBS="$LIBS $MYSQL_LIBS"
    fi
  
    mysql_lib=""
    LIBS="$LIBS -lz -lm"
    AC_CHECK_LIB(mysqlclient, mysql_init, [
  		old_CPPFLAGS=$CPPFLAGS
  		if test "$MYSQL_INCLUDE" != ""; then
  			CPPFLAGS="$CPPFLAGS $MYSQL_INCLUDE"
  		fi
  		AC_CHECK_HEADER(mysql.h, [
  			if test "$MYSQL_INCLUDE" != ""; then
  				MYSQL_CFLAGS="$MYSQL_CFLAGS $MYSQL_INCLUDE"
  			fi
  
  			AC_CHECK_LIB(mysqlclient, mysql_ssl_set, [
  				AC_DEFINE(HAVE_MYSQL_SSL,, [Define if your MySQL library has SSL functions])
  				if test "x$have_openssl" = "yes"; then
  				  ssl_define="#define HAVE_OPENSSL"
  				else
  				  ssl_define=""
  				fi
  				AC_TRY_COMPILE([
  				  $ssl_define
  				  #include <mysql.h>
  				], [
  				  mysql_ssl_set(0, 0, 0, 0, 0, 0);
  				], [
  					AC_DEFINE(HAVE_MYSQL_SSL_CIPHER,, [Define if your MySQL library supports setting cipher])
  
  					AC_TRY_COMPILE([
  					  $ssl_define
  					  #include <mysql.h>
  					], [
  					  int i = MYSQL_OPT_SSL_VERIFY_SERVER_CERT;
  					], [
  						AC_DEFINE(HAVE_MYSQL_SSL_VERIFY_SERVER_CERT,, [Defineif your MySQL library supports verifying the name in the SSL certificate])
  					])
  				])
  			])
  			
  			have_mysql=yes
  			AC_DEFINE(HAVE_MYSQL,, [Build with MySQL support])
  			found_sql_drivers="$found_sql_drivers mysql"
  		], [
  		  if test $want_mysql = yes; then
  		    AC_ERROR([Can't build with MySQL support: mysql.h not found])
  		  fi
  		])
  		CPPFLAGS=$old_CPPFLAGS
    ], [
      if test $want_mysql = yes; then
        AC_ERROR([Can't build with MySQL support: libmysqlclient not found])
      fi
    ])
  
    if test $have_mysql != yes; then
      MYSQL_LIBS=
      MYSQL_CFLAGS=
    fi
    LIBS=$old_LIBS
  fi
])
