/* Build with extra debugging checks */
#undef DEBUG

/* Disable asserts */
#undef DISABLE_ASSERTS

/* Build with rawlogging feature */
#undef BUILD_RAWLOG

/* Build with SSL/TLS support */
#undef HAVE_SSL
#undef HAVE_GNUTLS
#undef HAVE_OPENSSL

/* build with IPv6 support */
#undef HAVE_IPV6

/* Define if you have struct tm->tm_gmtoff */
#undef HAVE_TM_GMTOFF

/* Define if you have struct iovec */
#undef HAVE_STRUCT_IOVEC

#undef USERINFO_PASSWD
#undef USERINFO_PASSWD_FILE
#undef USERINFO_SHADOW
#undef USERINFO_PAM
#undef USERINFO_VPOPMAIL

#undef AUTH_PAM_USERPASS
#undef HAVE_PAM_SETCRED

/* How to implement I/O loop */
#undef IOLOOP_SELECT
#undef IOLOOP_POLL

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

/* Define if you have uintmax_t (C99 type) */
#undef HAVE_UINTMAX_T

/* Define if you have socklen_t */
#undef HAVE_SOCKLEN_T

/* Define if you have Linux-compatible mremap() */
#undef HAVE_LINUX_MREMAP

/* Define if you have Linux-compatible sendfile() */
#undef HAVE_LINUX_SENDFILE

/* Define if you have FreeBSD-compatible sendfile() */
#undef HAVE_FREEBSD_SENDFILE

/* Define if you have fdatasync() */
#undef HAVE_FDATASYNC
