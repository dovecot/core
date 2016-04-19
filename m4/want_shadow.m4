AC_DEFUN([DOVECOT_WANT_SHADOW], [
  have_shadow=no
  if test $want_shadow != no; then
    AC_CHECK_FUNC(getspnam, [
      AC_CHECK_HEADER(shadow.h, [
        AC_DEFINE(PASSDB_SHADOW,, [Build with shadow support])
        have_shadow=yes
      ], [
        if test $want_shadow = yes; then
          AC_ERROR([Can't build with shadow support: shadow.h not found])
        fi
      ])
    ], [
      if test $want_shadow = yes; then
        AC_ERROR([Can't build with shadow support: getspnam() not found])
      fi
    ])
  fi
  if test $have_shadow = no; then
    not_passdb="$not_passdb shadow"
  else
    passdb="$passdb shadow"
  fi
]) 
