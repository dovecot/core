#ifndef LIB_H
#define LIB_H

/* default lib includes */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* default system includes - keep these at minimum.. */
#include <stddef.h> /* Solaris defines NULL wrong unless this is used */
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

typedef struct buffer buffer_t;
typedef struct buffer string_t;

struct istream;
struct ostream;

typedef void lib_atexit_callback_t(void);

#include "array-decl.h" /* ARRAY*()s may exist in any header */
#include "hash-decl.h" /* HASH_TABLE*()s may exist in any header */
#include "strfuncs.h"
#include "strnum.h"

size_t nearest_power(size_t num) ATTR_CONST;
int close_keep_errno(int *fd);

/* Call the given callback at the beginning of lib_deinit(). The main
   difference to atexit() is that liblib's memory allocation and logging
   functions are still available. Also if lib_atexit() is called multiple times
   to the same callback, it's added only once. */
void lib_atexit(lib_atexit_callback_t *callback);

void lib_init(void);
void lib_deinit(void);

#endif
