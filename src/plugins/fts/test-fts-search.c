/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "fts-api.h"
#include "fts-search-scores.h"

static const struct fts_score_map mso_dest_before[] = {
	{ .uid = 1, .score = 0.1 },
	{ .uid = 2, .score = 0.2 },
};
static const struct fts_score_map mso_src[] = {
	{ .uid = 0, .score = 1.0 },
	{ .uid = 1, .score = 0.9 },
};
/* mso_dest_before "OR" mso_src should result in: */
static const struct fts_score_map mso_dest_after[] = {
	{ .uid = 0, .score = 1.0 },
	{ .uid = 1, .score = 0.9 },
	{ .uid = 2, .score = 0.2 },
};

static void test_merge_scores_or(void)
{
	ARRAY_TYPE(fts_score_map) dest, src;
	const struct fts_score_map *dest_map;
	unsigned int dest_count;

	test_begin("merge_scores_or");

	t_array_init(&dest, N_ELEMENTS(mso_dest_before));
	array_append(&dest, mso_dest_before, N_ELEMENTS(mso_dest_before));
	t_array_init(&src, N_ELEMENTS(mso_src));
	array_append(&src, mso_src, N_ELEMENTS(mso_src));

	fts_search_merge_scores_or(&dest, &src);

	dest_map = array_get(&dest, &dest_count);
	test_assert(dest_count == N_ELEMENTS(mso_dest_after));
	for (unsigned int i = 0;
	     i < dest_count && i < N_ELEMENTS(mso_dest_after); i++) {
		test_assert_idx(dest_map[i].uid == mso_dest_after[i].uid, i);
		test_assert_idx(dest_map[i].score == mso_dest_after[i].score, i);
	}

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_merge_scores_or,
		NULL
	};
	return test_run(test_functions);
}
