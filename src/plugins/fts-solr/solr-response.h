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

struct solr_response_parser *
solr_response_parser_init(pool_t result_pool, struct istream *input);
void solr_response_parser_deinit(struct solr_response_parser **_parser);

int solr_response_parse(struct solr_response_parser *parser,
			struct solr_result ***box_results_r);

#endif
