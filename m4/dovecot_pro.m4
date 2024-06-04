dnl Sets defines for the pro edition

AC_DEFUN([SET_PRO_DEFINES], [
  AC_DEFINE_UNQUOTED(DOVECOT_NAME, "$PACKAGE_NAME Pro", [Dovecot name])
  AC_DEFINE_UNQUOTED(DOVECOT_EDITION, "Pro", [Dovecot edition])

  AC_DEFINE([DOVECOT_PRO_EDITION],, [Define this if you want Dovecot Pro defaults])
])
