#ifndef FTS_SEARCH_SCORES_H
#define FTS_SEARCH_SCORES_H

#include "fts-api.h"

/* Raise dest scores to the src scores for UIDs that exist in both. Both
   arrays must be sorted by UID. */
void fts_search_merge_scores_and(ARRAY_TYPE(fts_score_map) *dest,
				 const ARRAY_TYPE(fts_score_map) *src);
/* Merge src scores into dest, adding missing UIDs and keeping the higher
   score for UIDs that exist in both. Both arrays must be sorted by UID. */
void fts_search_merge_scores_or(ARRAY_TYPE(fts_score_map) *dest,
				const ARRAY_TYPE(fts_score_map) *src);

#endif
