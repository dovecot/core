AC_DEFUN([DOVECOT_C_STATIC_ARRAY], [
  AC_CACHE_CHECK([if we can use C99 static in array sizes],i_cv_c99_static_arrays,[
    AC_TRY_COMPILE([
      void foo(int arr[static 20]);
    ], [
    ], [
      i_cv_c99_static_arrays=yes
    ], [
      i_cv_c99_static_arrays=no
    ])
  ])

  if test $i_cv_c99_static_arrays = yes; then
    static_value=static
  else
    static_value=
  fi
  AC_DEFINE_UNQUOTED(STATIC_ARRAY, $static_value, [C99 static array])
])
