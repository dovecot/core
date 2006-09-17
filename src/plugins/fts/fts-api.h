#ifndef __FTS_API_H
#define __FTS_API_H

#include "seq-range-array.h"

struct fts_backend *
fts_backend_init(const char *backend_name, const char *path);
void fts_backend_deinit(struct fts_backend *backend);

struct fts_backend_build_context *
fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r);
int fts_backend_build_more(struct fts_backend_build_context *ctx, uint32_t uid,
			   const void *data, size_t size);
int fts_backend_build_deinit(struct fts_backend_build_context *ctx);

int fts_backend_lookup(struct fts_backend *backend, const char *key,
		       ARRAY_TYPE(seq_range) *result);
int fts_backend_filter(struct fts_backend *backend, const char *key,
		       ARRAY_TYPE(seq_range) *result);

#endif
