#ifndef BSEARCH_INSERT_POS_H
#define BSEARCH_INSERT_POS_H

/* Binary search template - getdata must be the name of a pure function
   or a function-like macro that takes the two obvious parameters. */
#define BINARY_NUMERIC_SEARCH(getdata, data, count, value, idx_r)	\
	unsigned int idx, left_idx, right_idx;        \
						      \
	i_assert((count) < INT_MAX);                  \
	left_idx = 0; right_idx = (count);	      \
	while (left_idx < right_idx) {                \
		idx = (left_idx + right_idx) / 2;     \
						      \
		if (getdata(data, idx) < (value))     \
			left_idx = idx+1;             \
		else if (getdata(data, idx) > (value))\
			right_idx = idx;              \
		else {                                \
			*(idx_r) = idx;               \
			return TRUE;                  \
		}                                     \
	}                                             \
	return FALSE

#define BINARY_SEARCH_ARRAY_GET(array, index) ((array)[(index)])
#define BINARY_NUMBER_SEARCH(data, count, value, idx_r)			\
	BINARY_NUMERIC_SEARCH(BINARY_SEARCH_ARRAY_GET, data, count, value, idx_r);

/* If key is found, returns TRUE and sets idx_r to the position where the key
   was found. If key isn't found, returns FALSE and sets idx_r to the position
   where the key should be inserted. */
bool ATTR_NOWARN_UNUSED_RESULT
bsearch_insert_pos(const void *key, const void *base, unsigned int nmemb,
		   size_t size, int (*cmp)(const void *, const void *),
		   unsigned int *idx_r);
#define bsearch_insert_pos(key, base, nmemb, size, cmp, idx_r) \
	bsearch_insert_pos(key, base, nmemb, size - \
		CALLBACK_TYPECHECK(cmp, int (*)(typeof(const typeof(*key) *), \
						typeof(const typeof(*base) *))), \
		(int (*)(const void *, const void *))cmp, idx_r)

bool ATTR_NOWARN_UNUSED_RESULT
array_bsearch_insert_pos_i(const struct array *array, const void *key,
			   int (*cmp)(const void *, const void *),
			   unsigned int *idx_r);
#define array_bsearch_insert_pos(array, key, cmp, idx_r) \
	array_bsearch_insert_pos_i(&(array)->arr - \
		CALLBACK_TYPECHECK(cmp, int (*)(typeof(const typeof(*key) *), \
						typeof(*(array)->v))), \
		(const void *)key, (int (*)(const void *, const void *))cmp, idx_r)

#endif
