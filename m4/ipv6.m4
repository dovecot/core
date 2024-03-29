dnl **
dnl ** IPv6 support
dnl **

AC_DEFUN([DOVECOT_IPV6], [
  have_ipv6=no
  AC_MSG_CHECKING([for IPv6])
  AC_CACHE_VAL(i_cv_type_in6_addr,
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>]],
  [[struct in6_addr i; (void)i;]])],
  [i_cv_type_in6_addr=yes],
  [i_cv_type_in6_addr=no])])
  AS_IF([test $i_cv_type_in6_addr = yes], [
          AC_DEFINE(HAVE_IPV6,, [Build with IPv6 support])
          have_ipv6=yes
  ], [
          AC_MSG_ERROR(cannot build without IPv6 support.)
  ])
  AC_MSG_RESULT($i_cv_type_in6_addr)
])
