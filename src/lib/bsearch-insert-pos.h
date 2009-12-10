#ifndef BSEARCH_INSERT_POS_H
#define BSEARCH_INSERT_POS_H

/* Binary search template */
#define BINARY_NUMBER_SEARCH(data, count, value, idx_r) \
	unsigned int idx, left_idx, right_idx;        \
						      \
	idx = 0; left_idx = 0; right_idx = (count);   \
	while (left_idx < right_idx) {                \
		idx = (left_idx + right_idx) / 2;     \
						      \
		if ((data)[idx] < (value))            \
			left_idx = idx+1;             \
		else if ((data)[idx] > (value))       \
			right_idx = idx;              \
		else {                                \
			*(idx_r) = idx;               \
			return TRUE;                  \
		}                                     \
	}                                             \
	return FALSE

/* If key is found, returns TRUE and sets idx_r to the position where the key
   was found. If key isn't found, returns FALSE and sets idx_r to the position
   where the key should be inserted. */
bool bsearch_insert_pos(const void *key, const void *base, unsigned int nmemb,
			size_t size, int (*cmp)(const void *, const void *),
			unsigned int *idx_r);

bool array_bsearch_insert_pos_i(const struct array *array, const void *key,
				int (*cmp)(const void *, const void *),
				unsigned int *idx_r);
#ifdef CONTEXT_TYPE_SAFETY
#define array_bsearch_insert_pos(array, key, cmp, idx_r) \
	({(void)(1 ? 0 : cmp(key, ARRAY_TYPE_CAST_CONST(array)NULL)); \
	array_bsearch_insert_pos_i(&(array)->arr, (const void *)key, \
		(int (*)(const void *, const void *))cmp, idx_r); })
#else
#define array_bsearch_insert_pos(array, key, cmp, idx_r) \
	array_bsearch_insert_pos_i(&(array)->arr, (const void *)key, \
		(int (*)(const void *, const void *))cmp, idx_r)
#endif

#endif
