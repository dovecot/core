dnl Our implementation of AC_C_FLEXIBLE_ARRAY_MEMBER.
dnl Use it until autoconf 2.61+ becomes more widely used
AC_DEFUN([DOVECOT_C_FLEXIBLE_ARRAY_MEMBER], [
  AC_CACHE_CHECK([if we can use C99-like flexible array members],i_cv_c99_flex_arrays,[
    AC_TRY_COMPILE([
      struct foo {
        int x;
        char y[];
      };
    ], [
      struct foo foo;
    ], [
      i_cv_c99_flex_arrays=yes
    ], [
      i_cv_c99_flex_arrays=no
    ])
  ])
  
  if test $i_cv_c99_flex_arrays = yes; then
    flexible_value=
  else
    flexible_value=1
  fi
  AC_DEFINE_UNQUOTED(FLEXIBLE_ARRAY_MEMBER, $flexible_value, [How to define flexible array members in structs])
])
