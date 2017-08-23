AC_DEFUN([DOVECOT_RANDOM],[
	AC_CHECK_HEADER([sys/random.h], [
          AC_CHECK_FUNCS([getrandom])
          AC_CHECK_DECLS([getrandom], [], [], [[#include <sys/random.h>]])
        ])
])
