/* Build with SSL/TLS support */
#undef HAVE_SSL

/* build with IPv6 support */
#undef HAVE_IPV6

/* Define if you have struct tm->tm_gmtoff */
#undef HAVE_TM_GMTOFF

#undef USERINFO_PASSWD
#undef USERINFO_PASSWD_FILE
#undef USERINFO_SHADOW
#undef USERINFO_PAM
#undef AUTH_PAM_USERPASS

/* IMAP capabilities */
#undef CAPABILITY_STRING

/* Index file compatibility flags */
#undef MAIL_INDEX_COMPAT_FLAGS

/* Required memory alignment */
#undef MEM_ALIGN_SIZE

/* If set to 64, enables 64bit off_t for some systems (eg. Linux, Solaris) */
#undef _FILE_OFFSET_BITS

/* Maximum value for uoff_t */
#undef OFF_T_MAX

/* printf()-format for uoff_t, eg. "u" or "lu" or "llu" */
#undef PRIuUOFF_T

/* What type should be used for uoff_t */
#undef UOFF_T_INT
#undef UOFF_T_LONG
#undef UOFF_T_LONG_LONG

/* Maximum value for ssize_t */
#undef SSIZE_T_MAX

/* printf()-format for size_t, eg. "u" or "llu" */
#undef PRIuSIZE_T

/* What type should be used for largest_t */
#undef LARGEST_T_LONG
#undef LARGEST_T_LONG_LONG
