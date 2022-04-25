dnl TEST_WITH(name, value, [plugin])
AC_DEFUN([TEST_WITH], [
  want=want_`echo $1|sed s/-/_/g`
  AS_IF([test "$2" = yes || test "$2" = no || test "$2" = auto], [
    eval $want=$2
  ], [test "$2" = plugin], [
    AS_IF([test "$3" = "plugin"], [
      eval $want=plugin
    ], [
      AC_MSG_ERROR(--with-$1=plugin not supported)
    ])
  ], [test "$(echo $2|grep -c '^/' 2>/dev/null)" -gt 0], [
    AC_MSG_ERROR(--with-$1=path not supported. You may want to use instead:
CPPFLAGS=-I$2/include LDFLAGS=-L$2/lib ./configure --with-$1)
  ], [
    AC_MSG_ERROR(--with-$1: Unknown value: $2)
  ])
])
