AC_DEFUN([DOVECOT_CRYPT], [
  AC_CHECK_FUNC(crypt,, [
    AC_CHECK_LIB(crypt, crypt, [
      AUTH_LIBS="-lcrypt $AUTH_LIBS"
      CRYPT_LIBS="-lcrypt"
    ], [
      AC_MSG_ERROR([crypt() wasn't found])
    ])
  ])
  AC_SUBST(CRYPT_LIBS)
])
