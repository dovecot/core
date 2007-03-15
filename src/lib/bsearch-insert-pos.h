#ifndef __BSEARCH_INSERT_POS
#define __BSEARCH_INSERT_POS

/* If key is found, returns TRUE and sets idx_r to the position where the key
   was found. If key isn't found, returns FALSE and sets idx_r to the position
   where the key should be inserted. */
bool bsearch_insert_pos(const void *key, const void *base, unsigned int nmemb,
			size_t size, int (*cmp)(const void *, const void *),
			unsigned int *idx_r);

#endif
