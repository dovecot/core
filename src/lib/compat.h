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

#ifndef HAVE_UINTMAX_T
#  if SIZEOF_LONG_LONG > 0
typedef unsigned long long uintmax_t;
#  else
typedef unsigned long uintmax_t;
#  endif
#endif

#ifndef HAVE_UINT_FAST32_T
#  if SIZEOF_INT >= 4
typedef unsigned int uint_fast32_t;
#  else
typedef unsigned long uint_fast32_t;
#  endif
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#  define CMP_DEV_T(a, b) (major(a) == major(b) && minor(a) == minor(b))
#elif !defined (DEV_T_STRUCT)
#  define CMP_DEV_T(a, b) ((a) == (b))
#else
#  error I do not know how to compare dev_t
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

struct const_iovec {
	const void *iov_base;
	size_t iov_len;
};

#ifndef HAVE_STRUCT_IOVEC
struct iovec {
	void *iov_base;
	size_t iov_len;
};
#endif

#ifndef HAVE_WRITEV
#  define writev my_writev
struct iovec;
ssize_t my_writev(int fd, const struct iovec *iov, int iov_len);
#endif

#if !defined (HAVE_PREAD) || defined (PREAD_WRAPPERS)
#  ifndef IN_COMPAT_C
#    define pread my_pread
#    define pwrite my_pwrite
#  endif
ssize_t my_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t my_pwrite(int fd, const void *buf, size_t count, off_t offset);
#endif

#ifndef HAVE_SETEUID
#  define seteuid my_seteuid
int my_seteuid(uid_t euid);
#endif

#ifndef HAVE_LIBGEN_H
#  define basename my_basename
char *my_basename(char *path);
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

#ifdef EDQUOT
#  define ENOSPACE(errno) ((errno) == ENOSPC || (errno) == EDQUOT)
#else
#  define ENOSPACE(errno) ((errno) == ENOSPC)
#endif

/* EPERM is returned sometimes if device doesn't support such modification */
#ifdef EROFS
#  define ENOACCESS(errno) \
	((errno) == EACCES || (errno) == EROFS || (errno) == EPERM)
#else
#  define ENOACCESS(errno) ((errno) == EACCES || (errno) == EPERM)
#endif

#define ENOTFOUND(errno) \
	((errno) == ENOENT || (errno) == ENOTDIR || (errno) == ELOOP)

#endif
