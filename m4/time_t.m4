AC_DEFUN([DOVECOT_TIME_T], [
  AC_TYPEOF(time_t, long int long-long unsigned-int unsigned-long unsigned-long-long)
  case "$typeof_time_t" in
    long)
      timet_len="l"
      i_cv_signed_time_t=yes
      ;;
    int)
      timet_len=""
      i_cv_signed_time_t=yes
      ;;
    "long long")
      timet_len="ll"
      i_cv_signed_time_t=yes
      ;;
    "unsigned int")
      timet_len=""
      i_cv_signed_time_t=no
      ;;
    "unsigned long")
      timet_len="l"
      i_cv_signed_time_t=no
      ;;
    "unsigned long long")
      timet_len="ll"
      i_cv_signed_time_t=no
      ;;
    *)
      AC_MSG_ERROR([Unsupported time_t type])
      ;;
  esac
  if test $i_cv_signed_time_t = yes; then
    AC_DEFINE(TIME_T_SIGNED,, [Define if your time_t is signed])
    timet_d_fmt="$timet_len"d
  else
    timet_d_fmt="$timet_len"u
  fi
  timet_x_fmt="$timet_len"x

  AC_DEFINE_UNQUOTED(PRIdTIME_T, "$timet_d_fmt", [printf() fmt for dec time_t])
  AC_DEFINE_UNQUOTED(PRIxTIME_T, "$timet_x_fmt", [printf() fmt for hex time_t])
])
