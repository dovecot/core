AC_DEFUN([DOVECOT_LIBCAP],[
 if test $want_libcap != no; then
   AC_CHECK_LIB(cap, cap_init, [
     AC_DEFINE(HAVE_LIBCAP,, [libcap is installed for cap_init()])
     LIBCAP="-lcap"
     AC_SUBST(LIBCAP)
   ], [
     if test "$want_libcap" = "yes"; then
       AC_ERROR([Can't build with libcap support: libcap not found])
     fi
   ])
 fi
])
