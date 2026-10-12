/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "fts-api.h"
#include "fts-search-scores.h"

void
fts_search_merge_scores_and(ARRAY_TYPE(fts_score_map) *dest,
			    const ARRAY_TYPE(fts_score_map) *src)
{
	struct fts_score_map *dest_map;
	const struct fts_score_map *src_map;
	unsigned int desti, srci, dest_count, src_count;

	dest_map = array_get_modifiable(dest, &dest_count);
	src_map = array_get(src, &src_count);

	/* arg_scores are summed to current scores. we could drop UIDs that
	   don't exist in both, but that's just extra work so don't bother */
	for (desti = srci = 0; desti < dest_count && srci < src_count;) {
		if (dest_map[desti].uid < src_map[srci].uid)
			desti++;
		else if (dest_map[desti].uid > src_map[srci].uid)
			srci++;
		else {
			if (dest_map[desti].score < src_map[srci].score)
				dest_map[desti].score = src_map[srci].score;
			desti++; srci++;
		}
	}
}

void
fts_search_merge_scores_or(ARRAY_TYPE(fts_score_map) *dest,
			   const ARRAY_TYPE(fts_score_map) *src)
{
	ARRAY_TYPE(fts_score_map) src2;
	const struct fts_score_map *src_map, *src2_map;
	unsigned int srci, src2i, src_count, src2_count;

	t_array_init(&src2, array_count(dest));
	array_append_array(&src2, dest);
	array_clear(dest);

	src_map = array_get(src, &src_count);
	src2_map = array_get(&src2, &src2_count);

	/* add any missing UIDs to current scores. if any existing UIDs have
	   lower scores than in arg_scores, increase them. */
	for (srci = src2i = 0; srci < src_count || src2i < src2_count;) {
		if (src2i == src2_count ||
		    src_map[srci].uid < src2_map[src2i].uid) {
			array_push_back(dest, &src_map[srci]);
			srci++;
		} else if (srci == src_count ||
			   src_map[srci].uid > src2_map[src2i].uid) {
			array_push_back(dest, &src2_map[src2i]);
			src2i++;
		} else {
			i_assert(src_map[srci].uid == src2_map[src2i].uid);
			if (src_map[srci].score > src2_map[src2i].score)
				array_push_back(dest, &src_map[srci]);
			else
				array_push_back(dest, &src2_map[src2i]);
			srci++; src2i++;
		}
	}
}
