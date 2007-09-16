#ifndef SAFE_MEMSET_H
#define SAFE_MEMSET_H

/* memset() guaranteed not to get optimized away by compiler.
   Should be used instead of memset() when clearing any sensitive data. */
void safe_memset(void *data, int c, size_t size);

#endif
