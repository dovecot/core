AC_DEFUN([DOVECOT_WANT_SODIUM], [
  AS_IF([test "$want_sodium" != "no"], [
    PKG_CHECK_MODULES(LIBSODIUM, libsodium, [
      OLD_LIBS="$LIBS"
      LIBS="$LIBS $LIBSODIUM_LIBS"
      AC_CHECK_FUNC([crypto_pwhash_str_verify], [
        have_sodium=yes
        AUTH_LIBS="$AUTH_LIBS $LIBSODIUM_LIBS"
        AC_DEFINE(HAVE_LIBSODIUM, [1], [Define if you have libsodium])
      ])
      LIBS="$OLD_LIBS"
    ], [have_sodium=no])
    AS_IF([test "$want_sodium" = "yes" && test "$have_sodium" != "yes"] , [
      AC_ERROR([Can't build with libsodium: not found])
    ])
  ])
  AM_CONDITIONAL(BUILD_LIBSODIUM, test "$have_sodium" = "yes")
])
