#ifndef COMPAT_H
#define COMPAT_H

/* _ILP32 and _LP64 are common but not universal, make sure that exactly one
   of them is defined. */
#if !defined(_ILP32) && \
	(SIZEOF_INT == 4) && (SIZEOF_LONG == 4) && (SIZEOF_VOID_P == 4)
#  define _ILP32
#endif
#if !defined(_LP64) && \
	(SIZEOF_INT == 4) && (SIZEOF_LONG == 8) && (SIZEOF_VOID_P == 8)
#  define _LP64
#endif
#if defined(_ILP32) && defined(_LP64)
#  error "Cannot have both _ILP32 and _LP64 defined"
#elif !defined(_ILP32) && !defined(_LP64)
#  error "Must have one of _ILP32 and _LP64 defined"
#endif

/* well, this is obviously wrong since it assumes it's 64bit, but older
   GCCs don't define it and we really want it. */
#ifndef LLONG_MAX
#  define LLONG_MAX 9223372036854775807LL
#endif

#if ((__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 3)) && \
	defined(HAVE_TYPEOF)) && !defined(__cplusplus)
#  define HAVE_TYPE_CHECKS
#endif

/* We really want NULL to be a pointer, since we have various type-checks
   that may result in compiler warnings/errors if it's not. Do this only when
   type checking is used - it's not otherwise needed and causes compiling
   problems with e.g. Sun C compiler. */
#ifdef HAVE_TYPE_CHECKS
#  undef NULL
#  define NULL ((void *)0)
#endif

#ifndef __has_extension
  #define __has_extension(x) 0  // Compatibility with non-clang compilers.
#endif

#if (defined(__GNUC__) && __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)) || \
    (defined(__clang__) && (__has_extension(attribute_deprecated_with_message)))
#  define HAVE_ATTR_DEPRECATED
int rand(void) __attribute__((deprecated("Do not use rand, use i_rand")));
int rand_r(unsigned int*) __attribute__((deprecated("Do not use rand_r, use i_rand")));
#endif

#ifndef __cplusplus
#ifdef HAVE__BOOL
typedef _Bool bool;
#else
typedef int bool;
#endif
#endif

#if defined (HAVE_UOFF_T)
/* native support */
#elif defined (UOFF_T_INT)
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

/* WORDS_BIGENDIAN needs to be undefined if not enabled */
#if defined(WORDS_BIGENDIAN) && WORDS_BIGENDIAN == 0
#  undef WORDS_BIGENDIAN
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#  ifdef HAVE_SYS_MKDEV_H
#    include <sys/mkdev.h> /* UnixWare */
#  endif
#  define CMP_DEV_T(a, b) (major(a) == major(b) && minor(a) == minor(b))
#elif !defined (DEV_T_STRUCT)
#  define CMP_DEV_T(a, b) ((a) == (b))
#else
#  error I do not know how to compare dev_t
#endif

#ifdef HAVE_STAT_XTIM
#  define HAVE_ST_NSECS
#  define ST_ATIME_NSEC(st) ((unsigned long)(st).st_atim.tv_nsec)
#  define ST_MTIME_NSEC(st) ((unsigned long)(st).st_mtim.tv_nsec)
#  define ST_CTIME_NSEC(st) ((unsigned long)(st).st_ctim.tv_nsec)
#elif defined (HAVE_STAT_XTIMESPEC)
#  define HAVE_ST_NSECS
#  define ST_ATIME_NSEC(st) ((unsigned long)(st).st_atimespec.tv_nsec)
#  define ST_MTIME_NSEC(st) ((unsigned long)(st).st_mtimespec.tv_nsec)
#  define ST_CTIME_NSEC(st) ((unsigned long)(st).st_ctimespec.tv_nsec)
#else
#  define ST_ATIME_NSEC(st) 0UL
#  define ST_MTIME_NSEC(st) 0UL
#  define ST_CTIME_NSEC(st) 0UL
#endif

#ifdef HAVE_ST_NSECS
/* TRUE if a nanosecond timestamp from struct stat matches another nanosecond.
   If nanoseconds aren't supported in struct stat, returns always TRUE (useful
   with NFS if some hosts support nanoseconds and others don't). */
#  define ST_NTIMES_EQUAL(ns1, ns2) ((ns1) == (ns2))
#else
#  define ST_NTIMES_EQUAL(ns1, ns2) TRUE
#endif

#define CMP_ST_MTIME(st1, st2) \
	((st1)->st_mtime == (st2)->st_mtime && \
	 ST_NTIMES_EQUAL(ST_MTIME_NSEC(*(st1)), ST_MTIME_NSEC(*(st2))))
#define CMP_ST_CTIME(st1, st2) \
	((st1)->st_ctime == (st2)->st_ctime && \
	 ST_NTIMES_EQUAL(ST_CTIME_NSEC(*(st1)), ST_CTIME_NSEC(*(st2))))

/* strcasecmp(), strncasecmp() */
#ifndef HAVE_STRCASECMP
#  ifdef HAVE_STRICMP
#    define strcasecmp stricmp
#    define strncasecmp strnicmp
#  else
#    define strcasecmp i_my_strcasecmp
#    define strncasecmp i_my_strncasecmp
int i_my_strcasecmp(const char *s1, const char *s2);
int i_my_strncasecmp(const char *s1, const char *s2, size_t max_chars);
#  endif
#endif

#ifndef HAVE_INET_ATON
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  define inet_aton i_my_inet_aton
int i_my_inet_aton(const char *cp, struct in_addr *inp);
#endif

#ifndef HAVE_VSYSLOG
#  define vsyslog i_my_vsyslog
void i_my_vsyslog(int priority, const char *format, va_list args);
#endif

#ifndef HAVE_GETPAGESIZE
#  define getpagesize i_my_getpagesize
int i_my_getpagesize(void);
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

/* IOV_MAX should be in limits.h nowadays. Linux still (2005) requires
   defining _XOPEN_SOURCE to get that value. UIO_MAXIOV works with it though,
   so use it instead. 16 is the lowest acceptable value for all OSes. */
#ifndef IOV_MAX
#  include <sys/uio.h>
#  ifdef UIO_MAXIOV
#    define IOV_MAX UIO_MAXIOV
#  else
#    define IOV_MAX 16
#  endif
#endif

#ifndef HAVE_WRITEV
#  define writev i_my_writev
struct iovec;
ssize_t i_my_writev(int fd, const struct iovec *iov, int iov_len);
#endif

#if !defined(HAVE_PREAD) || defined(PREAD_WRAPPERS) || defined(PREAD_BROKEN)
#  ifndef IN_COMPAT_C
#    define pread i_my_pread
#    define pwrite i_my_pwrite
#  endif
ssize_t i_my_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t i_my_pwrite(int fd, const void *buf, size_t count, off_t offset);
#endif

#ifndef HAVE_SETEUID
#  define seteuid i_my_seteuid
int i_my_seteuid(uid_t euid);
#endif

#ifndef HAVE_SETEGID
#  define setegid i_my_setegid
int i_my_setegid(gid_t egid);
#endif

#ifndef HAVE_LIBGEN_H
#  define basename i_my_basename
char *i_my_basename(char *path);
#endif

#ifdef HAVE_OLD_VSNPRINTF
#  include <stdio.h>
#  define vsnprintf i_my_vsnprintf
int i_my_vsnprintf(char *str, size_t size, const char *format, va_list ap);
#endif

#ifndef HAVE_CLOCK_GETTIME
#  include <time.h>
#  undef CLOCK_REALTIME
#  define CLOCK_REALTIME 1
#  define clock_gettime i_my_clock_gettime
int i_my_clock_gettime(int clk_id, struct timespec *tp);
#endif

/* ctype.h isn't safe with signed chars,
   use our own instead if really needed */
#define i_toupper(x) ((char) toupper((int) (unsigned char) (x)))
#define i_tolower(x) ((char) tolower((int) (unsigned char) (x)))
#define i_isalnum(x) (isalnum((int) (unsigned char) (x)) != 0)
#define i_isalpha(x) (isalpha((int) (unsigned char) (x)) != 0)
#define i_isascii(x) (isascii((int) (unsigned char) (x)) != 0)
#define i_isblank(x) (isblank((int) (unsigned char) (x)) != 0)
#define i_iscntrl(x) (iscntrl((int) (unsigned char) (x)) != 0)
#define i_isdigit(x) (isdigit((int) (unsigned char) (x)) != 0)
#define i_isgraph(x) (isgraph((int) (unsigned char) (x)) != 0)
#define i_islower(x) (islower((int) (unsigned char) (x)) != 0)
#define i_isprint(x) (isprint((int) (unsigned char) (x)) != 0)
#define i_ispunct(x) (ispunct((int) (unsigned char) (x)) != 0)
#define i_isspace(x) (isspace((int) (unsigned char) (x)) != 0)
#define i_isupper(x) (isupper((int) (unsigned char) (x)) != 0)
#define i_isxdigit(x) (isxdigit((int) (unsigned char) (x)) != 0)

#ifndef EOVERFLOW
#  define EOVERFLOW ERANGE
#endif

#ifdef EDQUOT
#  define ENOSPACE(errno) ((errno) == ENOSPC || (errno) == EDQUOT)
#  define ENOQUOTA(errno) ((errno) == EDQUOT)
#else
/* probably all modern OSes have EDQUOT, but just in case one doesn't assume
   that ENOSPC is the same as "over quota". */
#  define ENOSPACE(errno) ((errno) == ENOSPC)
#  define ENOQUOTA(errno) ((errno) == ENOSPC)
#endif

/* EPERM is returned sometimes if device doesn't support such modification */
#ifdef EROFS
#  define ENOACCESS(errno) \
	((errno) == EACCES || (errno) == EROFS || (errno) == EPERM)
#else
#  define ENOACCESS(errno) ((errno) == EACCES || (errno) == EPERM)
#endif

#define ENOTFOUND(errno) \
	((errno) == ENOENT || (errno) == ENOTDIR || \
	 (errno) == ELOOP || (errno) == ENAMETOOLONG)

#define ECANTLINK(errno) \
	((errno) == EXDEV || (errno) == EMLINK || (errno) == EPERM)

/* Returns TRUE if unlink() failed because it attempted to delete a directory */
#define UNLINK_EISDIR(errno) \
	((errno) == EPERM || /* POSIX */ \
	 (errno) == EISDIR) /* Linux */

/* EBUSY is given by some NFS implementations */
#define EDESTDIREXISTS(errno) \
	((errno) == EEXIST || (errno) == ENOTEMPTY || (errno) == EBUSY)

/* fstat() returns ENOENT instead of ESTALE with some Linux versions */
#define ESTALE_FSTAT(errno) \
	((errno) == ESTALE || (errno) == ENOENT)

#if !defined(_POSIX_SYNCHRONIZED_IO) && \
    defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && \
    (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1060)
/* OS X Snow Leopard has fdatasync(), but no prototype for it. */
int fdatasync(int);
#endif

/* Try to keep IO operations at least this size */
#ifndef IO_BLOCK_SIZE
#  define IO_BLOCK_SIZE 8192
#endif
/* Default size for data blocks transferred over the network */
#ifndef NET_BLOCK_SIZE
#  define NET_BLOCK_SIZE (128*1024)
#endif

#if !defined(PIPE_BUF) && defined(_POSIX_PIPE_BUF)
#  define PIPE_BUF (8 * _POSIX_PIPE_BUF) /* for HURD */
#endif

#endif
