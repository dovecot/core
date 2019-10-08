#ifndef SOLR_CONNECTION_H
#define SOLR_CONNECTION_H

#include "solr-response.h"

struct solr_connection;
struct fts_solr_settings;

int solr_connection_init(const struct fts_solr_settings *solr_set,
			 const struct ssl_iostream_settings *ssl_client_set,
			 struct solr_connection **conn_r,
			 const char **error_r);
void solr_connection_deinit(struct solr_connection **conn);

int solr_connection_select(struct solr_connection *conn, const char *query,
			   pool_t pool, struct solr_result ***box_results_r);
int solr_connection_post(struct solr_connection *conn, const char *cmd);

struct solr_connection_post *
solr_connection_post_begin(struct solr_connection *conn);
void solr_connection_post_more(struct solr_connection_post *post,
			       const unsigned char *data, size_t size);
int solr_connection_post_end(struct solr_connection_post **post);

#endif
