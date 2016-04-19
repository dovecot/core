AC_DEFUN([DOVECOT_WANT_CDB], [
  if test $want_cdb != no; then
    AC_CHECK_LIB(cdb, cdb_init, [
      AC_CHECK_HEADER(cdb.h, [
        DICT_LIBS="$DICT_LIBS -lcdb"
        dict_drivers="$dict_drivers cdb"
        AC_DEFINE(BUILD_CDB,, [Build with CDB support])
      ], [
        if test $want_cdb = yes; then
          AC_ERROR([Can't build with CDB support: cdb.h not found])
        fi
      ])
    ], [
      if test $want_cdb = yes; then
        AC_ERROR([Can't build with CDB support: libcdb not found])
      fi
    ])
  fi
])
