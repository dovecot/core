AC_DEFUN([DOVECOT_WANT_DB], [
  if test $want_db != no; then
    AC_CACHE_CHECK([db_env_create in -ldb],i_cv_have_db_env_create,[
      old_LIBS=$LIBS
      LIBS="$LIBS -ldb"
      AC_TRY_LINK([
        #include <db.h>
      ], [
        db_env_create(0, 0);
      ], [
        i_cv_have_db_env_create=yes
      ], [
        i_cv_have_db_env_create=no
      ])
      LIBS=$old_LIBS
    ])
    if test $i_cv_have_db_env_create = yes; then
      AC_CHECK_HEADER(db.h, [
        DICT_LIBS="$DICT_LIBS -ldb"
        dict_drivers="$dict_drivers db"
        AC_DEFINE(BUILD_DB,, [Build with Berkeley DB support])
      ], [
        if test $want_db = yes; then
          AC_ERROR([Can't build with db support: db.h not found])
        fi
      ])
    else
      if test $want_db = yes; then
        AC_ERROR([Can't build with db support: libdb not found])
      fi
    fi
  fi
])
