#ifndef SOLR_RESPONSE_H
#define SOLR_RESPONSE_H

#include "seq-range-array.h"
#include "fts-api.h"

struct solr_result {
	const char *box_id;

	ARRAY_TYPE(seq_range) uids;
	ARRAY_TYPE(fts_score_map) scores;
};

#endif
