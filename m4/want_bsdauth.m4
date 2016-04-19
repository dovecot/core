AC_DEFUN([DOVECOT_WANT_BSDAUTH], [
  have_bsdauth=no
  if test $want_bsdauth != no; then
          AC_CHECK_FUNC(auth_userokay, [
                  AC_DEFINE(PASSDB_BSDAUTH,, [Build with BSD authentication support])
                  have_bsdauth=yes
          ], [
            if test $want_bsdauth = yes; then
              AC_ERROR([Can't build with BSD authentication support: auth_userokay() not found])
            fi
          ])
  fi
  if test $have_bsdauth = no; then
    not_passdb="$not_passdb bsdauth"
  else
    passdb="$passdb bsdauth"
  fi
])
