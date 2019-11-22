dnl * make sure size_t isn't signed. we'd probably work fine with it, but
dnl * it's more likely vulnerable to buffer overflows. Anyway, C99 specifies
dnl * that it's unsigned and only some old systems define it as signed.
AC_DEFUN([DOVECOT_SIZE_T_SIGNED], [
  AC_CACHE_CHECK([whether size_t is signed],i_cv_signed_size_t,[
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
      #include <sys/types.h>
      #include <stdlib.h>
      int arr[(size_t)-1 > 0 ? 1 : -1];
    ]])],[
      i_cv_signed_size_t=no
    ],[
      i_cv_signed_size_t=yes
  
      echo
      echo "Your system's size_t is a signed integer, Dovecot isn't designed to"
      echo "support it. It probably works just fine, but it's less resistant to"
      echo "buffer overflows. If you're not worried about this and still want to"
      echo "compile Dovecot, set ignore_signed_size=1 environment."
    
      if test "$ignore_signed_size" = ""; then
        AC_MSG_ERROR([aborting])
      fi
      echo "..ignoring as requested.."
    ],[])
  ])
  dnl Note: we check size_t rather than ssize_t here, because on OSX 10.2
  dnl ssize_t = int and size_t = unsigned long. We're mostly concerned about
  dnl printf format here, so check the size_t one.
  AC_TYPEOF(size_t, unsigned-int unsigned-long unsigned-long-long)
  case "$typeof_size_t" in
    "unsigned long")
      ssizet_max=LONG_MAX
      sizet_fmt="lu"
      ;;
    "unsigned long long")
      ssizet_max=LLONG_MAX
      sizet_fmt="llu"
      ;;
    *)
      dnl older systems didn't have ssize_t, default to int
      ssizet_max=INT_MAX
      sizet_fmt="u"
  
      if test "$typeof_size_t" = ""; then
        AC_DEFINE(size_t, unsigned int, [Define to 'unsigned int' if you don't have it])
        AC_DEFINE(ssize_t, int, [Define to 'int' if you don't have it])
      fi
      ;;
  esac
])
