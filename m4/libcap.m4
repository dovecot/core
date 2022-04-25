AC_DEFUN([DOVECOT_LIBCAP],[
 AS_IF([test $want_libcap != no], [
   AC_CHECK_LIB(cap, cap_init, [
     AC_DEFINE(HAVE_LIBCAP,, [libcap is installed for cap_init()])
     LIBCAP="-lcap"
     AC_SUBST(LIBCAP)
   ], [
     AS_IF([test "$want_libcap" = "yes"], [
       AC_MSG_ERROR(cannot build with libcap support: libcap not found)
     ])
   ])
 ])
])
