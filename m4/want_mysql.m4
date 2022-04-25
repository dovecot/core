AC_DEFUN([DOVECOT_WANT_MYSQL], [
  have_mysql=no
  AS_IF([test $want_mysql != no], [
    AC_CHECK_PROG(MYSQL_CONFIG, mysql_config, mysql_config, missing)
    AS_IF([test $MYSQL_CONFIG = missing], [
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
    ], [
      MYSQL_INCLUDE="`$MYSQL_CONFIG --include`"
      MYSQL_LIBS="`$MYSQL_CONFIG --libs`"
    ])
  
    old_LIBS=$LIBS
    AS_IF([test "$MYSQL_LIBS" != ""], [
      LIBS="$LIBS $MYSQL_LIBS"
    ])
  
    mysql_lib=""
    LIBS="$LIBS -lz -lm"
    AC_CHECK_LIB(mysqlclient, mysql_init, [
  		old_CPPFLAGS=$CPPFLAGS
  		AS_IF([test "$MYSQL_INCLUDE" != ""], [
  			CPPFLAGS="$CPPFLAGS $MYSQL_INCLUDE"
  		])
  		AC_CHECK_HEADER(mysql.h, [
  			AS_IF([test "$MYSQL_INCLUDE" != ""], [
  				MYSQL_CFLAGS="$MYSQL_CFLAGS $MYSQL_INCLUDE"
  			])
  
  			AC_CHECK_LIB(mysqlclient, mysql_ssl_set, [
  				AC_DEFINE(HAVE_MYSQL_SSL,, [Define if your MySQL library has SSL functions])
  				AS_IF([test "$have_openssl" = "yes"], [
  				  ssl_define="#define HAVE_OPENSSL"
  				], [
  				  ssl_define=""
  				])
  				AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  				  $ssl_define
  				  #include <mysql.h>
  				]], [[
				  mysql_ssl_set(0, 0, 0, 0, 0, 0);
  				]])],[
  					AC_DEFINE(HAVE_MYSQL_SSL_CIPHER,, [Define if your MySQL library supports setting cipher])
  
  					AC_COMPILE_IFELSE([_au_m4_changequote([,])AC_LANG_PROGRAM([[
  					  $ssl_define
  					  #include <mysql.h>
  					]], [[
  					  int i = MYSQL_OPT_SSL_VERIFY_SERVER_CERT;
  					]])], [
  						AC_DEFINE(HAVE_MYSQL_SSL_VERIFY_SERVER_CERT,, [Defineif your MySQL library supports verifying the name in the SSL certificate])
  					], [], [])
  				],[])
  			])
  			
  			have_mysql=yes
  			AC_DEFINE(HAVE_MYSQL,, [Build with MySQL support])
  			found_sql_drivers="$found_sql_drivers mysql"
  		], [
  		  AS_IF([test $want_mysql = yes], [
  		    AC_MSG_ERROR(cannot build with MySQL support: mysql.h not found)
  		  ])
  		])
  		CPPFLAGS=$old_CPPFLAGS
    ], [
      AS_IF([$want_mysql = yes], [
        AC_MSG_ERROR(cannot build with MySQL support: libmysqlclient not found)
      ])
    ])
  
    AS_IF([test $have_mysql != yes], [
      MYSQL_LIBS=
      MYSQL_CFLAGS=
    ])
    LIBS=$old_LIBS
  ])
])
