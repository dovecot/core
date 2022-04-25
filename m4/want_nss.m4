AC_DEFUN([DOVECOT_WANT_NSS], [
  have_nss=no
  AS_IF([test $want_nss != no], [
    AS_IF([test $have_modules != yes], [
      AS_IF([test $want_nss = yes], [
        AC_MSG_ERROR(cannot build with NSS support: Dynamic modules not supported)
      ])
    ], [
      AC_CACHE_CHECK([for NSS support],i_cv_have_nss,[
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
          #include <nss.h>
        ]], [[
          enum nss_status status = NSS_STATUS_TRYAGAIN;
        ]])],[
          i_cv_have_nss=yes
        ], [
          i_cv_have_nss=no
        ])
      ])
      AS_IF([test $i_cv_have_nss = yes], [
        AC_DEFINE(USERDB_NSS,, [Build with NSS module support])
        have_nss=yes
      ], [
        AS_IF([test $want_nss = yes], [
          AC_MSG_ERROR(cannot build with NSS support: nss.h not found or not usable)
        ])
      ])
    ])
  ])
  
  AS_IF([test $have_nss = no], [
    not_userdb="$not_userdb nss"
  ], [
    userdb="$userdb nss"
  ])
])
