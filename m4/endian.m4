dnl **
dnl ** Endianness
dnl **

dnl At least Apple's gcc supports __BIG_ENDIAN__ and __LITTLE_ENDIAN__
dnl defines. Use them if possible to allow cross-compiling.
AC_DEFUN([DOVECOT_ENDIAN], [
  AC_CACHE_CHECK([if __BIG_ENDIAN__ or __LITTLE_ENDIAN__ is defined],i_cv_have___big_endian__,[
    AC_TRY_COMPILE([
      #if !(__BIG_ENDIAN__ || __LITTLE_ENDIAN__)
      #error nope
      #endif
    ], [
    ], [
      i_cv_have___big_endian__=yes
    ], [
      i_cv_have___big_endian__=no
    ])
  ])
  if test $i_cv_have___big_endian__ = yes; then
    AC_DEFINE(WORDS_BIGENDIAN, __BIG_ENDIAN__, [Define if your CPU is big endian])
  else
    AC_C_BIGENDIAN
  fi
])
