dnl TEST_WITH(name, value, [plugin])
AC_DEFUN([TEST_WITH], [
  want=want_`echo $1|sed s/-/_/g`
  if test $2 = yes || test $2 = no || test $2 = auto; then
    eval $want=$2
  elif test $2 = plugin; then
    if test "$3" = plugin; then
      eval $want=plugin
    else
      AC_ERROR([--with-$1=plugin not supported])
    fi
  elif `echo $2|grep '^/' >/dev/null`; then
    AC_ERROR([--with-$1=path not supported. You may want to use instead:
CPPFLAGS=-I$2/include LDFLAGS=-L$2/lib ./configure --with-$1])
  else
    AC_ERROR([--with-$1: Unknown value: $2])
  fi
])
