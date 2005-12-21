#ifndef __BSEARCH_INSERT_POS
#define __BSEARCH_INSERT_POS

/* If key is found, returns the pointer to it. If not, returns a pointer to
   where it should be inserted. */
void *bsearch_insert_pos(const void *key, const void *base, unsigned int nmemb,
			 size_t size, int (*cmp)(const void *, const void *));

#endif
