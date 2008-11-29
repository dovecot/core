#ifndef SOLR_CONNECTION_H
#define SOLR_CONNECTION_H

#include "seq-range-array.h"
#include "fts-api.h"

/* Returns TRUE if UID conversion was done, FALSE if uid should be skipped. */
typedef bool solr_uid_map_callback_t(const char *ns_prefix, const char *mailbox,
				     uint32_t uidvalidity, uint32_t *uid,
				     void *context);

struct solr_connection *solr_connection_init(const char *url, bool debug);
void solr_connection_deinit(struct solr_connection *conn);

void solr_connection_http_escape(struct solr_connection *conn, string_t *dest,
				 const char *str);

int solr_connection_select(struct solr_connection *conn, const char *query,
			   solr_uid_map_callback_t *callback, void *context,
			   ARRAY_TYPE(seq_range) *uids,
			   ARRAY_TYPE(fts_score_map) *scores);
int solr_connection_post(struct solr_connection *conn, const char *cmd);

struct solr_connection_post *
solr_connection_post_begin(struct solr_connection *conn);
void solr_connection_post_more(struct solr_connection_post *post,
			       const unsigned char *data, size_t size);
int solr_connection_post_end(struct solr_connection_post *post);

#endif
