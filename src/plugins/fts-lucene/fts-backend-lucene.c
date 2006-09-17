/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "lucene-wrapper.h"
#include "fts-lucene-plugin.h"

struct lucene_fts_backend {
	struct fts_backend backend;
	struct lucene_index *index;

	uint32_t last_uid;
};

static struct fts_backend *fts_backend_lucene_init(const char *path)
{
	struct lucene_fts_backend *backend;

	backend = i_new(struct lucene_fts_backend, 1);
	backend->backend = fts_backend_lucene;
	backend->index = lucene_index_init(path);
	return &backend->backend;
}

static void fts_backend_lucene_deinit(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	lucene_index_deinit(backend->index);
	i_free(backend);
}

static struct fts_backend_build_context *
fts_backend_lucene_build_init(struct fts_backend *_backend, uint32_t *last_uid_r)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct fts_backend_build_context *ctx;

	ctx = i_new(struct fts_backend_build_context, 1);
	ctx->backend = _backend;
	if (lucene_index_build_init(backend->index, &backend->last_uid) < 0)
		ctx->failed = TRUE;

	*last_uid_r = backend->last_uid;
	return ctx;
}

static int
fts_backend_lucene_build_more(struct fts_backend_build_context *ctx,
			      uint32_t uid, const unsigned char *data,
			      size_t size)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)ctx->backend;

	if (ctx->failed)
		return -1;

	i_assert(uid >= backend->last_uid);
	backend->last_uid = uid;

	return lucene_index_build_more(backend->index, uid, data, size);
}

static int
fts_backend_lucene_build_deinit(struct fts_backend_build_context *ctx)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)ctx->backend;
	int ret = ctx->failed ? -1 : 0;

	lucene_index_build_deinit(backend->index);
	i_free(ctx);
	return ret;
}

static int
fts_backend_lucene_lookup(struct fts_backend *_backend, const char *key,
			 ARRAY_TYPE(seq_range) *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	return lucene_index_lookup(backend->index, key, result);
}

static int
fts_backend_lucene_filter(struct fts_backend *_backend, const char *key,
			 ARRAY_TYPE(seq_range) *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	return lucene_index_filter(backend->index, key, result);
}

struct fts_backend fts_backend_lucene = {
	"lucene",
	TRUE,

	{
		fts_backend_lucene_init,
		fts_backend_lucene_deinit,
		fts_backend_lucene_build_init,
		fts_backend_lucene_build_more,
		fts_backend_lucene_build_deinit,
		fts_backend_lucene_lookup,
		fts_backend_lucene_filter
	}
};
