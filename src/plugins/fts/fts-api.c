/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

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

static const struct fts_backend *
fts_backend_class_lookup(const char *backend_name)
{
	const struct fts_backend *const *be;
	unsigned int i, count;

	if (array_is_created(&backends)) {
		be = array_get(&backends, &count);
		for (i = 0; i < count; i++) {
			if (strcmp(be[i]->name, backend_name) == 0)
				return be[i];
		}
	}
	return NULL;
}

struct fts_backend *
fts_backend_init(const char *backend_name, struct mailbox *box)
{
	const struct fts_backend *be;
	struct fts_backend *backend;

	be = fts_backend_class_lookup(backend_name);
	if (be == NULL) {
		i_error("Unknown FTS backend: %s", backend_name);
		return NULL;
	}

	backend = be->v.init(box);
	if (backend == NULL)
		return NULL;
	backend->box = box;
	return backend;
}

void fts_backend_deinit(struct fts_backend **_backend)
{
	struct fts_backend *backend = *_backend;

	*_backend = NULL;
	backend->v.deinit(backend);
}

int fts_backend_get_last_uid(struct fts_backend *backend, uint32_t *last_uid_r)
{
	return backend->v.get_last_uid(backend, last_uid_r);
}

int fts_backend_get_all_last_uids(struct fts_backend *backend, pool_t pool,
				  ARRAY_TYPE(fts_backend_uid_map) *last_uids)
{
	return backend->v.get_all_last_uids(backend, pool, last_uids);
}

int fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r,
			   struct fts_backend_build_context **ctx_r)
{
	int ret;

	i_assert(!backend->building);

	ret = backend->v.build_init(backend, last_uid_r, ctx_r);
	if (ret == 0)
		backend->building = TRUE;
	return ret;
}

int fts_backend_build_more(struct fts_backend_build_context *ctx, uint32_t uid,
			   const unsigned char *data, size_t size, bool headers)
{
	return ctx->backend->v.build_more(ctx, uid, data, size, headers);
}

int fts_backend_build_deinit(struct fts_backend_build_context **_ctx)
{
	struct fts_backend_build_context *ctx = *_ctx;

	*_ctx = NULL;
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
	int ret;

	i_assert(!backend->locked);

	ret = backend->v.lock(backend);
	if (ret > 0)
		backend->locked = TRUE;
	return ret;
}

void fts_backend_unlock(struct fts_backend *backend)
{
	i_assert(backend->locked);

	backend->locked = FALSE;
	backend->v.unlock(backend);
}

static void
fts_merge_maybies(ARRAY_TYPE(seq_range) *dest_maybe,
		  const ARRAY_TYPE(seq_range) *dest_definite,
		  const ARRAY_TYPE(seq_range) *src_maybe,
		  const ARRAY_TYPE(seq_range) *src_definite)
{
	ARRAY_TYPE(seq_range) src_unwanted;
	const struct seq_range *range;
	struct seq_range new_range;
	unsigned int i, count;
	uint32_t seq;

	/* add/leave to dest_maybe if at least one list has maybe,
	   and no lists have none */

	/* create unwanted sequences list from both sources */
	t_array_init(&src_unwanted, 128);
	new_range.seq1 = 0; new_range.seq2 = (uint32_t)-1;
	array_append(&src_unwanted, &new_range, 1);
	seq_range_array_remove_seq_range(&src_unwanted, src_maybe);
	seq_range_array_remove_seq_range(&src_unwanted, src_definite);

	/* drop unwanted uids */
	seq_range_array_remove_seq_range(dest_maybe, &src_unwanted);

	/* add uids that are in dest_definite and src_maybe lists */
	range = array_get(dest_definite, &count);
	for (i = 0; i < count; i++) {
		for (seq = range[i].seq1; seq <= range[i].seq2; seq++) {
			if (seq_range_exists(src_maybe, seq))
				seq_range_array_add(dest_maybe, 0, seq);
		}
	}
}

void fts_filter_uids(ARRAY_TYPE(seq_range) *definite_dest,
		     const ARRAY_TYPE(seq_range) *definite_filter,
		     ARRAY_TYPE(seq_range) *maybe_dest,
		     const ARRAY_TYPE(seq_range) *maybe_filter)
{
	T_BEGIN {
		fts_merge_maybies(maybe_dest, definite_dest,
				  maybe_filter, definite_filter);
	} T_END;
	/* keep only what exists in both lists. the rest is in
	   maybies or not wanted */
	seq_range_array_intersect(definite_dest, definite_filter);
}

static void fts_lookup_invert(ARRAY_TYPE(seq_range) *definite_uids,
			      const ARRAY_TYPE(seq_range) *maybe_uids)
{
	/* we'll begin by inverting definite UIDs */
	seq_range_array_invert(definite_uids, 1, (uint32_t)-1);

	/* from that list remove UIDs in the maybe list.
	   the maybe list itself isn't touched. */
	(void)seq_range_array_remove_seq_range(definite_uids, maybe_uids);
}

static int fts_backend_lookup(struct fts_backend *backend, const char *key,
			      enum fts_lookup_flags flags,
			      ARRAY_TYPE(seq_range) *definite_uids,
			      ARRAY_TYPE(seq_range) *maybe_uids)
{
	int ret;

	ret = backend->v.lookup(backend, key, flags & ~FTS_LOOKUP_FLAG_INVERT,
				definite_uids, maybe_uids);
	if (unlikely(ret < 0))
		return -1;
	if ((flags & FTS_LOOKUP_FLAG_INVERT) != 0)
		fts_lookup_invert(definite_uids, maybe_uids);
	return 0;
}

static int fts_backend_filter(struct fts_backend *backend, const char *key,
			      enum fts_lookup_flags flags,
			      ARRAY_TYPE(seq_range) *definite_uids,
			      ARRAY_TYPE(seq_range) *maybe_uids)
{
	ARRAY_TYPE(seq_range) tmp_definite, tmp_maybe;
	int ret;

	if (backend->v.filter != NULL) {
		return backend->v.filter(backend, key, flags,
					 definite_uids, maybe_uids);
	}

	/* do this ourself */
	i_array_init(&tmp_definite, 64);
	i_array_init(&tmp_maybe, 64);
	ret = fts_backend_lookup(backend, key, flags,
				 &tmp_definite, &tmp_maybe);
	if (ret < 0) {
		array_clear(definite_uids);
		array_clear(maybe_uids);
	} else {
		fts_filter_uids(definite_uids, &tmp_definite,
				maybe_uids, &tmp_maybe);
	}
	array_free(&tmp_maybe);
	array_free(&tmp_definite);
	return ret;
}

struct fts_backend_lookup_context *
fts_backend_lookup_init(struct fts_backend *backend)
{
	struct fts_backend_lookup_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("fts backend lookup", 256);
	ctx = p_new(pool, struct fts_backend_lookup_context, 1);
	ctx->pool = pool;
	ctx->backend = backend;
	p_array_init(&ctx->fields, pool, 8);
	return ctx;
}

void fts_backend_lookup_add(struct fts_backend_lookup_context *ctx,
			    const char *key, enum fts_lookup_flags flags)
{
	struct fts_backend_lookup_field *field;

	field = array_append_space(&ctx->fields);
	field->key = p_strdup(ctx->pool, key);
	field->flags = flags;
}

static int fts_backend_lookup_old(struct fts_backend_lookup_context *ctx,
				  ARRAY_TYPE(seq_range) *definite_uids,
				  ARRAY_TYPE(seq_range) *maybe_uids)
{
	const struct fts_backend_lookup_field *fields;
	unsigned int i, count;

	fields = array_get(&ctx->fields, &count);
	i_assert(count > 0);

	if (fts_backend_lookup(ctx->backend, fields[0].key, fields[0].flags,
			       definite_uids, maybe_uids) < 0)
		return -1;
	for (i = 1; i < count; i++) {
		if (fts_backend_filter(ctx->backend,
				       fields[i].key, fields[i].flags,
				       definite_uids, maybe_uids) < 0)
			return -1;
	}
	return 0;
}

int fts_backend_lookup_deinit(struct fts_backend_lookup_context **_ctx,
			      ARRAY_TYPE(seq_range) *definite_uids,
			      ARRAY_TYPE(seq_range) *maybe_uids,
			      ARRAY_TYPE(fts_score_map) *scores)
{
	struct fts_backend_lookup_context *ctx = *_ctx;
	int ret;

	*_ctx = NULL;
	if (ctx->backend->v.lookup2 != NULL) {
		ret = ctx->backend->v.lookup2(ctx, definite_uids, maybe_uids,
					      scores);
	} else {
		array_clear(scores);
		ret = fts_backend_lookup_old(ctx, definite_uids, maybe_uids);
	}
	pool_unref(&ctx->pool);
	return ret;
}
