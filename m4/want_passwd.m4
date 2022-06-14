AC_DEFUN([DOVECOT_WANT_PASSWD], [
  AS_IF([test "$want_passwd" != "no"], [
    AC_DEFINE(USERDB_PASSWD,, [Build with passwd support])
    AC_DEFINE(PASSDB_PASSWD,, [Build with passwd support])
    userdb="$userdb passwd"
    passdb="$passdb passwd"
  ], [
    not_passdb="$not_passdb passwd"
    not_userdb="$not_userdb passwd"
  ])
  
  AS_IF([test "$want_passwd_file" != "no"], [
    AC_DEFINE(USERDB_PASSWD_FILE,, [Build with passwd-file support])
    AC_DEFINE(PASSDB_PASSWD_FILE,, [Build with passwd-file support])
    userdb="$userdb passwd-file"
    passdb="$passdb passwd-file"
  ], [
    not_passdb="$not_passdb passwd-file"
    not_userdb="$not_userdb passwd-file"
  ])
])
