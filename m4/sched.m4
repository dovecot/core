AC_DEFUN([DOVECOT_SCHED], [
   AC_CHECK_HEADERS([sys/cpuset.h sched.h])
   AC_CHECK_FUNCS([sched_getaffinity cpuset_getaffinity])
])
