#ifndef LUCENE_WRAPPER_H
#define LUCENE_WRAPPER_H

#include "fts-api-private.h"

struct lucene_index *lucene_index_init(const char *path, const char *lock_path);
void lucene_index_deinit(struct lucene_index *index);

void lucene_index_select_mailbox(struct lucene_index *index,
				 const char *mailbox_name);
int lucene_index_get_last_uid(struct lucene_index *index, uint32_t *last_uid_r);

int lucene_index_build_init(struct lucene_index *index, uint32_t *last_uid_r);
int lucene_index_build_more(struct lucene_index *index, uint32_t uid,
			    const unsigned char *data, size_t size,
			    bool headers);
int lucene_index_build_deinit(struct lucene_index *index);

int lucene_index_expunge(struct lucene_index *index, uint32_t uid);

int lucene_index_lookup(struct lucene_index *index, enum fts_lookup_flags flags,
			const char *key, ARRAY_TYPE(seq_range) *result);

#endif
