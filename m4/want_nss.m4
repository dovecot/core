AC_DEFUN([DOVECOT_WANT_NSS], [
  have_nss=no
  if test $want_nss != no; then
    if test $have_modules != yes; then
      if test $want_nss = yes; then
        AC_ERROR([Can't build with NSS support: Dynamic modules not supported])
      fi
    else
      AC_CACHE_CHECK([for NSS support],i_cv_have_nss,[
        AC_TRY_COMPILE([
          #include <nss.h>
        ], [
          enum nss_status status = NSS_STATUS_TRYAGAIN;
        ], [
          i_cv_have_nss=yes
        ], [
          i_cv_have_nss=no
        ])
      ])
      if test $i_cv_have_nss = yes; then
        AC_DEFINE(USERDB_NSS,, [Build with NSS module support])
        have_nss=yes
      else
        if test $want_nss = yes; then
          AC_ERROR([Can't build with NSS support: nss.h not found or not usable])
        fi
      fi
    fi
  fi
  
  if test $have_nss = no; then
    not_userdb="$not_userdb nss"
  else
    userdb="$userdb nss"
  fi
])
