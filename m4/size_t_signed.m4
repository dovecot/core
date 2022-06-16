AC_DEFUN([DOVECOT_SIZE_T_SIGNED], [
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
