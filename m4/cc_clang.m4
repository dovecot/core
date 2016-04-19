dnl * clang check
AC_DEFUN([CC_CLANG],[
have_clang=no
if $CC -dM -E -x c /dev/null | grep __clang__ > /dev/null 2>&1; then
  have_clang=yes
fi
])
