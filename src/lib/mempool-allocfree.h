#ifndef __MEMPOOL_H
#define __MEMPOOL_H

#include "macros.h"

/* #define POOL_CHECK_LEAKS */

/* Memory allocated and reallocated (the new data in it) in pools is always
   zeroed, it will cost only a few CPU cycles and may well save some debug
   time. */

typedef struct Pool *Pool;

Pool pool_create(const char *name, unsigned int size);

void pool_ref(Pool pool);
void pool_unref(Pool pool);

#define p_new(pool, type, count) \
	((type *) p_malloc(pool, (unsigned) sizeof(type) * (count)))
void *p_malloc(Pool pool, unsigned int size);

void p_free(Pool pool, void *mem);
#define p_free_and_null(pool, rec) \
	STMT_START { \
          p_free(pool, rec); \
          (rec) = NULL; \
	} STMT_END

/* p_free_clean() should be used when pool is being destroyed, so freeing
   memory isn't needed for anything else than detecting memory leaks. */
#ifdef POOL_CHECK_LEAKS
#  define p_free_clean(pool, mem) p_free(pool, mem)
#else
#  define p_free_clean(pool, mem)
#endif

/* reallocate the `mem' to be exactly `size' */
void *p_realloc(Pool pool, void *mem, unsigned int size);
/* reallocate the `mem' to be at least `size' if it wasn't previously */
void *p_realloc_min(Pool pool, void *mem, unsigned int size);

/* Clear the pool. Memory allocated from pool before this call must not be
   used after. */
void p_clear(Pool pool);

#endif
