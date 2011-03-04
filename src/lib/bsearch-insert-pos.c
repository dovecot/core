/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"

bool bsearch_insert_pos(const void *key, const void *base, unsigned int nmemb,
			size_t size, int (*cmp)(const void *, const void *),
			unsigned int *idx_r)
{
	const void *p;
	unsigned int idx, left_idx, right_idx;
	int ret;

	idx = 0; left_idx = 0; right_idx = nmemb;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		p = CONST_PTR_OFFSET(base, idx * size);
		ret = cmp(key, p);
		if (ret > 0)
			left_idx = idx+1;
		else if (ret < 0)
			right_idx = idx;
		else {
			*idx_r = idx;
			return TRUE;
		}
	}

	if (left_idx > idx)
		idx++;

	*idx_r = idx;
	return FALSE;
}

bool array_bsearch_insert_pos_i(const struct array *array, const void *key,
				int (*cmp)(const void *, const void *),
				unsigned int *idx_r)
{
	return bsearch_insert_pos(key, array->buffer->data,
				  array_count_i(array),
				  array->element_size, cmp, idx_r);
}
