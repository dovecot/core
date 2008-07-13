#ifndef SOLR_CONNECTION_H
#define SOLR_CONNECTION_H

#include "seq-range-array.h"

struct solr_connection *solr_connection_init(const char *settings);
void solr_connection_deinit(struct solr_connection *conn);

void solr_connection_quote_str(struct solr_connection *conn, string_t *dest,
			       const char *str);

int solr_connection_select(struct solr_connection *conn, const char *query,
			   ARRAY_TYPE(seq_range) *uids);
int solr_connection_post(struct solr_connection *conn, const char *cmd);

struct solr_connection_post *
solr_connection_post_begin(struct solr_connection *conn);
void solr_connection_post_more(struct solr_connection_post *post,
			       const unsigned char *data, size_t size);
int solr_connection_post_end(struct solr_connection_post *post);

#endif
