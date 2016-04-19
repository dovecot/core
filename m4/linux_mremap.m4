dnl * Linux compatible mremap()
AC_DEFUN([DOVECOT_LINUX_MREMAP], [
  AC_CACHE_CHECK([Linux compatible mremap()],i_cv_have_linux_mremap,[
    AC_TRY_LINK([
      #include <unistd.h>
      #define __USE_GNU
      #include <sys/mman.h>
    ], [
      mremap(0, 0, 0, MREMAP_MAYMOVE);
    ], [
      i_cv_have_linux_mremap=yes
    ], [
      i_cv_have_linux_mremap=no
    ])
  ])
  if test $i_cv_have_linux_mremap = yes; then
    AC_DEFINE(HAVE_LINUX_MREMAP,, [Define if you have Linux-compatible mremap()])
  fi
])
