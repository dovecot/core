AC_DEFUN([DOVECOT_WANT_CDB], [
  AS_IF([test "$want_cdb" != "no"], [
    AC_CHECK_LIB(cdb, cdb_init, [
      AC_CHECK_HEADER(cdb.h, [
        DICT_LIBS="$DICT_LIBS -lcdb"
        dict_drivers="$dict_drivers cdb"
        AC_DEFINE(BUILD_CDB,, [Build with CDB support])
      ], [
        AS_IF([test "$want_cdb" = "yes"], [
          AC_MSG_ERROR(cannot build with CDB support: cdb.h not found)
        ])
      ])
    ], [
      AS_IF([test "$want_cdb" = "yes"], [
        AC_MSG_ERROR(cannot build with CDB support: libcdb not found)
      ])
    ])
  ])
])
