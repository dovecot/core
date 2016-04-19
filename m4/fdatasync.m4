AC_DEFUN([DOVECOT_FDATASYNC], [
  AC_SEARCH_LIBS(fdatasync, rt, [
    AC_DEFINE(HAVE_FDATASYNC,, [Define if you have fdatasync()])
  ])
])
