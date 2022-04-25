AC_DEFUN([DOVECOT_WANT_DB], [
  AS_IF([test $want_db != no], [
    AC_CACHE_CHECK([db_env_create in -ldb],i_cv_have_db_env_create,[
      old_LIBS=$LIBS
      LIBS="$LIBS -ldb"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        #include <db.h>
      ]], [[
        db_env_create(0, 0);
      ]])],[
        i_cv_have_db_env_create=yes
      ], [
        i_cv_have_db_env_create=no
      ])
      LIBS=$old_LIBS
    ])
    AS_IF([test $i_cv_have_db_env_create = yes], [
      AC_CHECK_HEADER(db.h, [
        DICT_LIBS="$DICT_LIBS -ldb"
        dict_drivers="$dict_drivers db"
        AC_DEFINE(BUILD_DB,, [Build with Berkeley DB support])
      ], [
        AS_IF([test $want_db = yes], [
          AC_MSG_ERROR(Can't build with db support: db.h not found)
        ])
      ])
    ], [
      AS_IF([test $want_db = yes], [
        AC_ERROR([Can't build with db support: libdb not found])
      ])
    ])
  ])
])
