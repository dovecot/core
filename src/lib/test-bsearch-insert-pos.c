/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "bsearch-insert-pos.h"

static int cmp_uint(const unsigned int *i1, const unsigned int *i2)
{
	return (int)*i1 - (int)*i2;
}

void test_bsearch_insert_pos(void)
{
	static const unsigned int input[] = {
		1, 5, 9, 15, 16, UINT_MAX,
		1, 5, 9, 15, 16, 17, UINT_MAX,
		UINT_MAX
	};
	static const unsigned int max_key = 18;
	const unsigned int *cur;
	unsigned int key, len, i, idx;
	bool success;

	cur = input;
	for (i = 0; cur[0] != UINT_MAX; i++) {
		for (len = 0; cur[len] != UINT_MAX; len++) ;
		for (key = 0; key < max_key; key++) {
			if (bsearch_insert_pos(&key, cur, len, sizeof(*cur),
					       cmp_uint, &idx))
				success = cur[idx] == key;
			else if (idx == 0)
				success = cur[0] > key;
			else if (idx == len)
				success = cur[len-1] < key;
			else {
				success = cur[idx-1] < key &&
					cur[idx+1] > key;
			}
			if (!success)
				break;
		}
		cur += len + 1;

		test_out(t_strdup_printf("bsearch_insert_pos(%d,%d)", i, key),
			 success);
	}
}
