#ifndef SOLR_RESPONSE_H
#define SOLR_RESPONSE_H

#include "seq-range-array.h"
#include "fts-api.h"

struct solr_response_parser;

struct solr_result {
	const char *box_id;

	ARRAY_TYPE(seq_range) uids;
	ARRAY_TYPE(fts_score_map) scores;
};

void solr_response_parser_init(struct solr_response_parser *parser,
			       pool_t result_pool);
void solr_response_parser_deinit(struct solr_response_parser *parser);

#endif
