AC_DEFUN([DOVECOT_WANT_VPOPMAIL], [
  have_vpopmail=no
  if test $want_vpopmail != no; then
          vpop_etc="$vpopmail_home/etc"
          AC_MSG_CHECKING([for vpopmail configuration at $vpop_etc/lib_deps])
          if ! test -f $vpop_etc/lib_deps; then
                  AC_MSG_RESULT(not found)
                  vpop_etc="$vpopmail_home"
                  AC_MSG_CHECKING([for vpopmail configuration at $vpop_etc/lib_deps])
          fi
          if test -f $vpop_etc/lib_deps; then
                  AUTH_CFLAGS="$AUTH_CFLAGS `cat $vpop_etc/inc_deps` $CFLAGS"
                  AUTH_LIBS="$AUTH_LIBS `cat $vpop_etc/lib_deps`"
                  AC_DEFINE(USERDB_VPOPMAIL,, [Build with vpopmail support])
                  AC_DEFINE(PASSDB_VPOPMAIL,, [Build with vpopmail support])
                  AC_MSG_RESULT(found)
                  have_vpopmail=yes
          else
                  AC_MSG_RESULT(not found)
                  if test $want_vpopmail = yes; then
                    AC_ERROR([Can't build with vpopmail support: $vpop_etc/lib_deps not found])
                  fi
          fi
  fi
  
  if test $have_vpopmail = no; then
    not_passdb="$not_passdb vpopmail"
    not_userdb="$not_userdb vpopmail"
  else
    userdb="$userdb vpopmail"
    passdb="$passdb vpopmail"
  fi
])
