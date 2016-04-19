AC_DEFUN([DOVECOT_SOCKPEERCRED], [
  AC_CHECK_TYPES([struct sockpeercred],,,[
  #include <sys/types.h>
  #include <sys/socket.h>
  ])
])
