AC_DEFUN([DOVECOT_WANT_PAM], [
  if test $want_pam != no; then
          AC_CHECK_LIB(pam, pam_start, [
                  have_pam=no
                  AC_CHECK_HEADER(security/pam_appl.h, [
                          AC_DEFINE(HAVE_SECURITY_PAM_APPL_H,,
                                    [Define if you have security/pam_appl.h])
                          have_pam=yes
                  ])
  
                  AC_CHECK_HEADER(pam/pam_appl.h, [
                          AC_DEFINE(HAVE_PAM_PAM_APPL_H,,
                                    [Define if you have pam/pam_appl.h])
                          have_pam=yes
                  ])
          ], [
            if test $want_pam = yes; then
              AC_ERROR([Can't build with PAM support: libpam not found])
            fi
          ])
  fi
  
  if test "$have_pam" = "yes"; then
    AUTH_LIBS="$AUTH_LIBS -lpam"
    AC_DEFINE(PASSDB_PAM,, [Build with PAM support])
    passdb="$passdb pam"
  
    AC_CHECK_LIB(pam, pam_setcred, [
      AC_DEFINE(HAVE_PAM_SETCRED,, [Define if you have pam_setcred()])
    ])
  elif test $want_pam = yes; then
    AC_ERROR([Can't build with PAM support: pam_appl.h not found])
  else
    not_passdb="$not_passdb pam"
  fi
])
