#ifndef __LUCENE_WRAPPER_H
#define __LUCENE_WRAPPER_H

#include "fts-api-private.h"

struct lucene_index *lucene_index_init(const char *path);
void lucene_index_deinit(struct lucene_index *index);

int lucene_index_select_mailbox(struct lucene_index *index,
				const char *mailbox_name);

int lucene_index_build_init(struct lucene_index *index, uint32_t *last_uid_r);
int lucene_index_build_more(struct lucene_index *index, uint32_t uid,
			    const unsigned char *data, size_t size);
int lucene_index_build_deinit(struct lucene_index *index);

int lucene_index_lookup(struct lucene_index *index, const char *key,
			ARRAY_TYPE(seq_range) *result);
int lucene_index_filter(struct lucene_index *index, const char *key,
			ARRAY_TYPE(seq_range) *result);

#endif
