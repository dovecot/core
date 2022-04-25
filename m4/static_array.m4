AC_DEFUN([DOVECOT_C_STATIC_ARRAY], [
  AC_CACHE_CHECK([if we can use C99 static in array sizes],i_cv_c99_static_arrays,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      void foo(unsigned char arr[static 20]);
    ]], [[
    ]])],[
      i_cv_c99_static_arrays=yes
    ],[
      i_cv_c99_static_arrays=no
    ])
  ])

  AS_IF([test $i_cv_c99_static_arrays = yes], [
    static_value=static
  ], [
    static_value=
  ])
  AC_DEFINE_UNQUOTED(STATIC_ARRAY, $static_value, [C99 static array])
])
