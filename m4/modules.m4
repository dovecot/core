dnl * dynamic modules?
AC_DEFUN([DOVECOT_MODULES], [
  AC_CHECK_FUNC(dlopen, [
    MODULE_LIBS="-export-dynamic"
  ], [
    AC_CHECK_LIB(dl, dlopen, [
      MODULE_LIBS="-export-dynamic -ldl"
      DLLIB=-ldl
    ], [
      AC_MSG_ERROR([dlopen() is missing - can't build without dynamic modules])
    ])
  ])
  AC_SUBST(MODULE_LIBS)
  AC_SUBST(DLLIB)

  dnl shrext_cmds comes from libtool.m4
  module=yes eval MODULE_SUFFIX=$shrext_cmds
  if test "$MODULE_SUFFIX" = ""; then
    # too old libtool?
    MODULE_SUFFIX=.so
  fi
  AC_DEFINE_UNQUOTED(MODULE_SUFFIX,"$MODULE_SUFFIX", [Dynamic module suffix])
  AC_SUBST(MODULE_SUFFIX)
])
