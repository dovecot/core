dnl Sets defines for the pro edition

AC_DEFUN([SET_PRO_DEFINES], [
  AC_DEFINE_UNQUOTED(DOVECOT_NAME, "$PACKAGE_NAME Pro", [Dovecot name])
  AC_DEFINE_UNQUOTED(DOVECOT_EDITION, "Pro", [Dovecot edition])
])
