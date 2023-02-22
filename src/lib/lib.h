#ifndef LIB_H
#define LIB_H

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  define __BSD_VISIBLE 1
#elif defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1
#endif
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

/* default lib includes */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* default system includes - keep these at minimum.. */
#include <stddef.h> /* Solaris defines NULL wrong unless this is used */
#include <stdlib.h>
#include <string.h> /* strcmp() etc. */
#ifdef HAVE_STRINGS_H
#  include <strings.h> /* strcasecmp() etc. */
#endif
#include <stdarg.h> /* va_list is used everywhere */
#include <limits.h> /* INT_MAX, etc. */
#include <errno.h> /* error checking is good */
#include <sys/types.h> /* many other includes want this */
#include <stdint.h> /* C99 int types, we mostly need uintmax_t */
#include <inttypes.h> /* PRI* macros */
#ifndef __cplusplus
#  include <stdbool.h>
#endif

#include "compat.h"
#include "macros.h"
#include "failures.h"

#include "malloc-overflow.h"
#include "data-stack.h"
#include "mempool.h"
#include "imem.h"
#include "byteorder.h"
#include "fd-util.h"

typedef struct buffer buffer_t;
typedef struct buffer string_t;

struct istream;
struct ostream;

typedef void lib_atexit_callback_t(void);

#include "array-decl.h" /* ARRAY*()s may exist in any header */
#include "bits.h"
#include "hash-decl.h" /* HASH_TABLE*()s may exist in any header */
#include "strfuncs.h"
#include "strnum.h"
#include "event-log.h"

#define LIB_ATEXIT_PRIORITY_HIGH -10
#define LIB_ATEXIT_PRIORITY_DEFAULT 0
#define LIB_ATEXIT_PRIORITY_LOW 10

#define static_assert_array_size(arr, count) \
	static_assert(N_ELEMENTS(arr) == (count), "array/enum size mismatch")

/* Using memcpy() with NULL pointers is undefined behavior. Make sure we don't
   do that. */
static inline void *i_memcpy(void *dest, const void *src, size_t n) {
	i_assert(dest != NULL && src != NULL);
	return memcpy(dest, src, n);
}
#ifndef __cplusplus
#  define memcpy(dest, src, n) i_memcpy(dest, src, n)
#endif

/* /dev/null opened as O_WRONLY. Opened at lib_init(), so it can be accessed
   also inside chroots. */
extern int dev_null_fd;

/* Call unlink(). If it fails, log an error including the source filename
   and line number. */
int i_unlink(const char *path, const char *source_fname,
	     unsigned int source_linenum);
#define i_unlink(path) i_unlink(path, __FILE__, __LINE__)
/* Same as i_unlink(), but don't log an error if errno=ENOENT. Returns 1 on
   unlink() success, 0 if errno=ENOENT, -1 on other errors. */
int i_unlink_if_exists(const char *path, const char *source_fname,
		       unsigned int source_linenum);
#define i_unlink_if_exists(path) i_unlink_if_exists(path, __FILE__, __LINE__)
/* Reset getopt() so it can be used for the next args. */
void i_getopt_reset(void);

/* Call the given callback at the beginning of lib_deinit(). The main
   difference to atexit() is that liblib's memory allocation and logging
   functions are still available. Also if lib_atexit() is called multiple times
   to the same callback, it's added only once. */
void lib_atexit(lib_atexit_callback_t *callback);
/* Specify the order in which the callback is called. Lowest numbered
   priorities are called first. lib_atexit() is called with priority=0. */
void lib_atexit_priority(lib_atexit_callback_t *callback, int priority);
/* Manually run the atexit callbacks. lib_deinit() also does this if not
   explicitly called. */
void lib_atexit_run(void);
/* Unless this or lib_deinit() is called, any unexpected exit() will result
   in abort(). This can be helpful in catching unexpected exits. */
void lib_set_clean_exit(bool set);
/* Same as lib_set_clean_exit(TRUE) followed by exit(status). */
void lib_exit(int status) ATTR_NORETURN;

void lib_init(void);
bool lib_is_initialized(void);
void lib_deinit(void);

uint32_t i_rand(void);
/* Returns a random integer < upper_bound. */
uint32_t i_rand_limit(uint32_t upper_bound);

static inline unsigned short i_rand_ushort(void)
{
        return i_rand_limit(USHRT_MAX + 1);
}

static inline unsigned char i_rand_uchar(void)
{
        return i_rand_limit(UCHAR_MAX + 1);
}

/* Returns a random integer >= min_val, and <= max_val. */
static inline uint32_t i_rand_minmax(uint32_t min_val, uint32_t max_val)
{
	i_assert(min_val <= max_val);
	return min_val + i_rand_limit(max_val - min_val + 1);
}

/* Cast time_t to uint32_t, assert the value fits. */
static inline uint32_t time_to_uint32(time_t ts)
{
	i_assert(ts >= 0);
	i_assert(ts <= UINT32_MAX);
	return (uint32_t)(ts & 0xffffffff);
}
/* Cast time_t to uint32_t, truncate the value if it does not fit. */
static inline uint32_t time_to_uint32_trunc(time_t ts)
{
	if (ts < 0)
		return 0;
	if (ts > UINT32_MAX)
		return UINT32_MAX;
	return (uint32_t)(ts & 0xffffffff);
}
#endif
