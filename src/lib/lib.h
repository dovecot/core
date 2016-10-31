#ifndef LIB_H
#define LIB_H

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

#ifdef HAVE_STDINT_H
#  include <stdint.h> /* C99 int types, we mostly need uintmax_t */
#endif

#include "compat.h"
#include "macros.h"
#include "failures.h"

#include "data-stack.h"
#include "mempool.h"
#include "imem.h"
#include "rand.h"

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

#define LIB_ATEXIT_PRIORITY_HIGH -10
#define LIB_ATEXIT_PRIORITY_DEFAULT 0
#define LIB_ATEXIT_PRIORITY_LOW 10

int close_keep_errno(int *fd);
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

void lib_init(void);
bool lib_is_initialized(void);
void lib_deinit(void);

#endif
