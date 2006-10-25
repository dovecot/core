#ifndef __FTS_API_H
#define __FTS_API_H

struct mailbox;

#include "seq-range-array.h"

struct fts_backend *
fts_backend_init(const char *backend_name, struct mailbox *box);
void fts_backend_deinit(struct fts_backend *backend);

/* Get the last_uid. */
int fts_backend_get_last_uid(struct fts_backend *backend, uint32_t *last_uid_r);

/* Initialize adding new data to the index. last_uid_r is set to the last UID
   that exists in the index. */
struct fts_backend_build_context *
fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r);
/* Add more contents to the index. The data must contain only full valid
   UTF-8 characters, but it doesn't need to be NUL-terminated. size contains
   the data size in bytes, not characters. */
int fts_backend_build_more(struct fts_backend_build_context *ctx, uint32_t uid,
			   const unsigned char *data, size_t size);
/* Finish adding new data to the index. */
int fts_backend_build_deinit(struct fts_backend_build_context *ctx);

/* Lookup key from the index and return the found UIDs in result. */
int fts_backend_lookup(struct fts_backend *backend, const char *key,
		       ARRAY_TYPE(seq_range) *result);
/* Drop UIDs from the result list for which the key doesn't exist. The idea
   is that with multiple search keywords you first lookup one and then filter
   the rest. */
int fts_backend_filter(struct fts_backend *backend, const char *key,
		       ARRAY_TYPE(seq_range) *result);

#endif
