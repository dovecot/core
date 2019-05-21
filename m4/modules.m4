dnl * dynamic modules?
AC_DEFUN([DOVECOT_MODULES], [
  have_modules=no
  AC_CHECK_FUNC(dlopen, [
    have_modules=yes
    MODULE_LIBS="-export-dynamic"
  ], [
    AC_CHECK_LIB(dl, dlopen, [
      have_modules=yes
      MODULE_LIBS="-export-dynamic -ldl"
      DLLIB=-ldl
    ])
  ])
  AC_SUBST(MODULE_LIBS)
  AC_SUBST(DLLIB)
])
