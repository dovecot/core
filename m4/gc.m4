dnl **
dnl ** Garbage Collector
dnl ** 

AC_DEFUN([DOVECOT_GC], [
  if test $want_gc != no; then
    AC_CHECK_LIB(gc, GC_malloc, [
      AC_CHECK_HEADERS(gc/gc.h gc.h)
      AC_DEFINE(USE_GC,, [Define if you want to use Boehm GC])
      LIBS="$LIBS -lgc"
    ], [
      if test $want_gc = yes; then
        AC_ERROR([Can't build with GC: libgc not found])
      fi
    ])
  fi
])
