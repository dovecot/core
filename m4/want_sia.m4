AC_DEFUN([DOVECOT_WANT_SIA], [
  have_sia=no
  if test $want_sia != no; then
          AC_CHECK_FUNC(sia_validate_user, [
                  AC_DEFINE(PASSDB_SIA,, [Build with Tru64 SIA support])
                  AUTH_LIBS="$AUTH_LIBS -depth_ring_search"
                  have_sia=yes
          ], [
            if test $want_sia = yes; then
              AC_ERROR([Can't build with SIA support: sia_validate_user() not found])
            fi
          ])
  fi
  
  if test $have_sia = no; then
    not_passdb="$not_passdb sia"
  else
    passdb="$passdb sia"
  fi
])
