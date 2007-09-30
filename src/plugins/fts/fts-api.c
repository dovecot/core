/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

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
	backend->v.deinit(backend);
}

int fts_backend_get_last_uid(struct fts_backend *backend, uint32_t *last_uid_r)
{
	return backend->v.get_last_uid(backend, last_uid_r);
}

struct fts_backend_build_context *
fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r)
{
	i_assert(!backend->building);

	backend->building = TRUE;

	return backend->v.build_init(backend, last_uid_r);
}

int fts_backend_build_more(struct fts_backend_build_context *ctx, uint32_t uid,
			   const unsigned char *data, size_t size, bool headers)
{
	return ctx->backend->v.build_more(ctx, uid, data, size, headers);
}

int fts_backend_build_deinit(struct fts_backend_build_context *ctx)
{
	ctx->backend->building = FALSE;
	return ctx->backend->v.build_deinit(ctx);
}

bool fts_backend_is_building(struct fts_backend *backend)
{
	return backend->building;
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

int fts_backend_lock(struct fts_backend *backend)
{
	return backend->v.lock(backend);
}

void fts_backend_unlock(struct fts_backend *backend)
{
	backend->v.unlock(backend);
}

int fts_backend_lookup(struct fts_backend *backend, enum fts_lookup_flags flags,
		       const char *key, ARRAY_TYPE(seq_range) *result)
{
	return backend->v.lookup(backend, flags, key, result);
}

int fts_backend_filter(struct fts_backend *backend, enum fts_lookup_flags flags,
		       const char *key, ARRAY_TYPE(seq_range) *result)
{
	ARRAY_TYPE(seq_range) tmp_result;
	int ret;

	if (backend->v.filter != NULL)
		return backend->v.filter(backend, flags, key, result);

	/* do this ourself */
	i_array_init(&tmp_result, 64);
	ret = fts_backend_lookup(backend, flags, key, &tmp_result);
	if (ret == 0) {
		const struct seq_range *range;
		unsigned int i, count;
		uint32_t next_seq = 1;

		range = array_get(&tmp_result, &count);
		for (i = 0; i < count; i++) {
			if (next_seq != range[i].seq1) {
				seq_range_array_remove_range(result, next_seq,
							     range[i].seq1 - 1);
			}
			next_seq = range[i].seq2 + 1;
		}

		range = array_get(result, &count);
		if (count > 0) {
			seq_range_array_remove_range(result, next_seq,
						     range[count-1].seq2);
		}
	}
	array_free(&tmp_result);
	return ret;
}
