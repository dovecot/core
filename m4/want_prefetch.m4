AC_DEFUN([DOVECOT_WANT_PREFETCH], [
  if test $want_prefetch_userdb != no; then
          AC_DEFINE(USERDB_PREFETCH,, [Build with prefetch userdb support])
          userdb="$userdb prefetch"
  else
          not_userdb="$not_userdb prefetch"
  fi
])
