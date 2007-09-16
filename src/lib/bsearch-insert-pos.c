/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
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

