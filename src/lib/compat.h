#ifndef __COMPAT_H
#define __COMPAT_H

/* well, this is obviously wrong since it assumes it's 64bit, but older
   GCCs don't define it and we really want it. */
#ifndef LLONG_MAX
#  define LLONG_MAX 9223372036854775807LL
#endif

#if defined (UOFF_T_INT)
typedef unsigned int uoff_t;
#elif defined (UOFF_T_LONG)
typedef unsigned long uoff_t;
#elif defined (UOFF_T_LONG_LONG)
typedef unsigned long long uoff_t;
#else
#  error uoff_t size not set
#endif

#if defined (LARGEST_T_LONG)
typedef unsigned long largest_t;
#elif defined (LARGEST_T_LONG_LONG)
typedef unsigned long long largest_t;
#else
#  error largest_t size not set
#endif

/* memmove() */
#ifndef HAVE_MEMMOVE
#  define memmove my_memmove
void *my_memmove(void *dest, const void *src, size_t n);
#endif

/* strcasecmp(), strncasecmp() */
#ifndef HAVE_STRCASECMP
#  ifdef HAVE_STRICMP
#    define strcasecmp stricmp
#    define strncasecmp strnicmp
#  else
#    define strcasecmp my_strcasecmp
#    define strncasecmp my_strncasecmp
int my_strcasecmp(const char *s1, const char *s2);
int my_strncasecmp(const char *s1, const char *s2, size_t max_chars);
#  endif
#endif

#ifndef HAVE_INET_ATON
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  define inet_aton my_inet_aton
int my_inet_aton(const char *cp, struct in_addr *inp);
#endif

#ifndef HAVE_VSYSLOG
#  define vsyslog my_vsyslog
void my_vsyslog(int priority, const char *format, va_list args);
#endif

#ifndef HAVE_GETPAGESIZE
#  define getpagesize my_getpagesize
int my_getpagesize(void);
#endif

#ifndef HAVE_FDATASYNC
#  define fdatasync fsync
#endif

#ifndef HAVE_STRUCT_IOVEC
struct iovec {
	void *iov_base;
	size_t iov_len;
};
#endif

#ifndef HAVE_WRITEV
#  define writev my_writev
struct iovec;
ssize_t my_writev(int fd, const struct iovec *iov, size_t iov_len);
#endif

/* ctype.h isn't safe with signed chars,
   use our own instead if really needed */
#define i_toupper(x) ((char) toupper((int) (unsigned char) (x)))
#define i_tolower(x) ((char) tolower((int) (unsigned char) (x)))
#define i_isalnum(x) isalnum((int) (unsigned char) (x))
#define i_isalpha(x) isalpha((int) (unsigned char) (x))
#define i_isascii(x) isascii((int) (unsigned char) (x))
#define i_isblank(x) isblank((int) (unsigned char) (x))
#define i_iscntrl(x) iscntrl((int) (unsigned char) (x))
#define i_isdigit(x) isdigit((int) (unsigned char) (x))
#define i_isgraph(x) isgraph((int) (unsigned char) (x))
#define i_islower(x) islower((int) (unsigned char) (x))
#define i_isprint(x) isprint((int) (unsigned char) (x))
#define i_ispunct(x) ispunct((int) (unsigned char) (x))
#define i_isspace(x) isspace((int) (unsigned char) (x))
#define i_isupper(x) isupper((int) (unsigned char) (x))
#define i_isxdigit(x) isxdigit((int) (unsigned char) (x))

#ifndef EOVERFLOW
#  define EOVERFLOW EINVAL
#endif

#endif
