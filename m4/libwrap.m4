AC_DEFUN([DOVECOT_LIBWRAP], [
  have_libwrap=no
  if test $want_libwrap != no; then
    AC_CHECK_HEADER(tcpd.h, [
      old_LIBS=$LIBS
  
      AC_CACHE_CHECK([whether we have libwrap],i_cv_have_libwrap,[
        AC_TRY_COMPILE([
          #include <tcpd.h>
          int allow_severity = 0;
          int deny_severity = 0;
        ], [
          request_init((void *)0);
        ], [
          i_cv_have_libwrap=yes
        ], [
          i_cv_have_libwrap=no
        ])
      ])
      if test $i_cv_have_libwrap = yes; then
        AC_DEFINE(HAVE_LIBWRAP,, [Define if you have libwrap])
        LIBWRAP_LIBS=-lwrap
        AC_SUBST(LIBWRAP_LIBS)
        have_libwrap=yes
      else
        if test "$want_libwrap" = "yes"; then
          AC_ERROR([Can't build with libwrap support: libwrap not found])
        fi
      fi
      LIBS=$old_LIBS
    ], [
      if test "$want_libwrap" = "yes"; then
        AC_ERROR([Can't build with libwrap support: tcpd.h not found])
      fi
    ])
  fi
  AM_CONDITIONAL(TCPWRAPPERS, test "$have_libwrap" = "yes")
])
