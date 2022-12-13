#ifndef COMPAT_H
#define COMPAT_H

#if defined(HAVE_TYPEOF) && !defined(__cplusplus)
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

#if !defined(static_assert) /* C23 */ && !defined(__cplusplus)
#  define static_assert _Static_assert
#endif

#if (defined(__GNUC__) && __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)) || \
    (defined(__clang__) && (__has_extension(attribute_deprecated_with_message)))
#  define HAVE_ATTR_DEPRECATED
int rand(void) __attribute__((deprecated("Do not use rand, use i_rand")));
int rand_r(unsigned int*) __attribute__((deprecated("Do not use rand_r, use i_rand")));
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

/* WORDS_BIGENDIAN needs to be undefined if not enabled */
#if defined(WORDS_BIGENDIAN) && WORDS_BIGENDIAN == 0
#  undef WORDS_BIGENDIAN
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#endif
#define CMP_DEV_T(a, b) (major(a) == major(b) && minor(a) == minor(b))

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

struct const_iovec {
	const void *iov_base;
	size_t iov_len;
};

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
