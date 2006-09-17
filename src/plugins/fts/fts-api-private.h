#ifndef __FTS_API_PRIVATE_H
#define __FTS_API_PRIVATE_H

#include "fts-api.h"

struct fts_backend_vfuncs {
	struct fts_backend *(*init)(const char *path);
	void (*deinit)(struct fts_backend *backend);

	struct fts_backend_build_context *
		(*build_init)(struct fts_backend *backend,
			      uint32_t *last_uid_r);
	int (*build_more)(struct fts_backend_build_context *ctx, uint32_t uid,
			  const void *data, size_t size);
	int (*build_deinit)(struct fts_backend_build_context *ctx);

	int (*lookup)(struct fts_backend *backend, const char *key,
		      ARRAY_TYPE(seq_range) *result);
	int (*filter)(struct fts_backend *backend, const char *key,
		      ARRAY_TYPE(seq_range) *result);
};

struct fts_backend {
	const char *name;
	struct fts_backend_vfuncs v;
};

struct fts_backend_build_context {
	struct fts_backend *backend;
};

void fts_backend_register(const struct fts_backend *backend);
void fts_backend_unregister(const char *name);

#endif
