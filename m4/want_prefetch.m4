AC_DEFUN([DOVECOT_WANT_PREFETCH], [
  AS_IF([test "$want_prefetch_userdb" != "no"], [
    AC_DEFINE(USERDB_PREFETCH,, [Build with prefetch userdb support])
    userdb="$userdb prefetch"
  ], [
    not_userdb="$not_userdb prefetch"
  ])
])
