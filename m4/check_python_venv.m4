dnl Define DOVECOT_CHECK_PYTHON_VENV function to be used in configure.ac
dnl Provide HAVE_VENV if we can access a virtual python environment,
dnl which might be necessary to build the documentation if so desired.

AC_DEFUN([DOVECOT_CHECK_PYTHON_VENV], [
  AM_PATH_PYTHON([3.6],,[:])
  AS_IF([test "${PYTHON}" != ":"], [
    AX_PYTHON_MODULE([venv],[])
  ])
  AM_CONDITIONAL([HAVE_VENV], [test "x${HAVE_PYMOD_VENV}" = "xyes"])
])
