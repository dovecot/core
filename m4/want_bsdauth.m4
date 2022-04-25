AC_DEFUN([DOVECOT_WANT_BSDAUTH], [
  have_bsdauth=no

  AS_IF([test "$want_bsdauth" != "no"], [
    AC_CHECK_FUNC(auth_userokay, [
      AC_DEFINE(PASSDB_BSDAUTH,, [Build with BSD authentication support])
      have_bsdauth=yes
    ], [
      AS_IF([test "$want_bsdauth" = "yes"], [
        AC_MSG_ERROR(cannot build with BSD authentication support: auth_userokay() not found)
      ])
    ])
  ])
  AS_IF([test "$have_bsdauth" = "no"], [
    not_passdb="$not_passdb bsdauth"
  ], [
    passdb="$passdb bsdauth"
  ])
])
