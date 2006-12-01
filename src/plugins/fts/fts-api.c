/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "fts-api-private.h"

static ARRAY_DEFINE(backends, const struct fts_backend *);

void fts_backend_register(const struct fts_backend *backend)
{
	if (!array_is_created(&backends))
		i_array_init(&backends, 4);
	array_append(&backends, &backend, 1);
}

void fts_backend_unregister(const char *name)
{
	const struct fts_backend *const *be;
	unsigned int i, count;

	be = array_get(&backends, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(be[i]->name, name) == 0) {
			array_delete(&backends, i, 1);
			break;
		}
	}
	if (i == count)
		i_panic("fts_backend_unregister(%s): unknown backend", name);

	if (count == 1)
		array_free(&backends);
}

struct fts_backend *
fts_backend_init(const char *backend_name, struct mailbox *box)
{
	const struct fts_backend *const *be;
	unsigned int i, count;

	if (array_is_created(&backends)) {
		be = array_get(&backends, &count);
		for (i = 0; i < count; i++) {
			if (strcmp(be[i]->name, backend_name) == 0)
				return be[i]->v.init(box);
		}
	}

	i_error("Unknown FTS backend: %s", backend_name);
	return NULL;
}

void fts_backend_deinit(struct fts_backend *backend)
{
	return backend->v.deinit(backend);
}

int fts_backend_get_last_uid(struct fts_backend *backend, uint32_t *last_uid_r)
{
	return backend->v.get_last_uid(backend, last_uid_r);
}

struct fts_backend_build_context *
fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r)
{
	return backend->v.build_init(backend, last_uid_r);
}

int fts_backend_build_more(struct fts_backend_build_context *ctx, uint32_t uid,
			   const unsigned char *data, size_t size)
{
	return ctx->backend->v.build_more(ctx, uid, data, size);
}

int fts_backend_build_deinit(struct fts_backend_build_context *ctx)
{
	return ctx->backend->v.build_deinit(ctx);
}

void fts_backend_expunge(struct fts_backend *backend, struct mail *mail)
{
	backend->v.expunge(backend, mail);
}

void fts_backend_expunge_finish(struct fts_backend *backend,
				struct mailbox *box, bool committed)
{
	backend->v.expunge_finish(backend, box, committed);
}

int fts_backend_lookup(struct fts_backend *backend, const char *key,
		       ARRAY_TYPE(seq_range) *result)
{
	return backend->v.lookup(backend, key, result);
}

int fts_backend_filter(struct fts_backend *backend, const char *key,
		       ARRAY_TYPE(seq_range) *result)
{
	return backend->v.filter(backend, key, result);
}
