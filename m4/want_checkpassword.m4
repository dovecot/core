AC_DEFUN([DOVECOT_WANT_CHECKPASSWORD], [
  if test $want_checkpassword != no; then
          AC_DEFINE(PASSDB_CHECKPASSWORD,, [Build with checkpassword passdb support])
          AC_DEFINE(USERDB_CHECKPASSWORD,, [Build with checkpassword userdb support])
          passdb="$passdb checkpassword"
          userdb="$userdb checkpassword"
  else
          not_passdb="$not_passdb checkpassword"
          not_userdb="$not_userdb checkpassword"
  fi
])
