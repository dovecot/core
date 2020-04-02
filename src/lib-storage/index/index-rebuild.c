/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-cache.h"
#include "mail-index-modseq.h"
#include "mailbox-list-private.h"
#include "mailbox-recent-flags.h"
#include "index-storage.h"
#include "index-rebuild.h"

static void
index_index_copy_vsize(struct index_rebuild_context *ctx,
		       struct mail_index_view *view,
		       uint32_t old_seq, uint32_t new_seq)
{
	const void *data;
	bool expunged;

	mail_index_lookup_ext(view, old_seq, ctx->box->mail_vsize_ext_id,
			      &data, &expunged);
	if (data != NULL && !expunged) {
		mail_index_update_ext(ctx->trans, new_seq,
				      ctx->box->mail_vsize_ext_id, data, NULL);
	}
}

static void
index_index_copy_cache(struct index_rebuild_context *ctx,
		       struct mail_index_view *view,
		       uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index_map *map;
	const void *data;
	uint32_t reset_id = 0;
	bool expunged;

	if (ctx->cache_ext_id == (uint32_t)-1)
		return;

	mail_index_lookup_ext_full(view, old_seq, ctx->cache_ext_id,
				   &map, &data, &expunged);
	if (expunged)
		return;

	if (!mail_index_ext_get_reset_id(view, map, ctx->cache_ext_id,
					 &reset_id) || reset_id == 0)
		return;

	if (!ctx->cache_used) {
		/* set reset id */
		ctx->cache_used = TRUE;
		ctx->cache_reset_id = reset_id;
		mail_index_ext_reset(ctx->trans, ctx->cache_ext_id,
				     ctx->cache_reset_id, TRUE);
	}
	if (ctx->cache_reset_id == reset_id) {
		mail_index_update_ext(ctx->trans, new_seq,
				      ctx->cache_ext_id, data, NULL);
	}
}

static void
index_index_copy_from_old(struct index_rebuild_context *ctx,
			  struct mail_index_view *view,
			  uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index *index = mail_index_view_get_index(view);
	const struct mail_index_record *rec;
	ARRAY_TYPE(keyword_indexes) old_keywords;
	struct mail_keywords *kw;
	uint64_t modseq;

	/* copy flags */
	rec = mail_index_lookup(view, old_seq);
	mail_index_update_flags(ctx->trans, new_seq,
				MODIFY_REPLACE, rec->flags);

	/* copy keywords */
	t_array_init(&old_keywords, 32);
	mail_index_lookup_keywords(view, old_seq, &old_keywords);
	kw = mail_index_keywords_create_from_indexes(index, &old_keywords);
	mail_index_update_keywords(ctx->trans, new_seq, MODIFY_REPLACE, kw);
	mail_index_keywords_unref(&kw);

	/* copy modseq */
	modseq = mail_index_modseq_lookup(view, old_seq);
	mail_index_update_modseq(ctx->trans, new_seq, modseq);

	index_index_copy_vsize(ctx, view, old_seq, new_seq);
	index_index_copy_cache(ctx, view, old_seq, new_seq);
}

void index_rebuild_index_metadata(struct index_rebuild_context *ctx,
				  uint32_t new_seq, uint32_t uid)
{
	uint32_t old_seq;

	if (mail_index_lookup_seq(ctx->view, uid, &old_seq)) {
		/* the message exists in the old index.
		   copy the metadata from it. */
		index_index_copy_from_old(ctx, ctx->view, old_seq, new_seq);
	} else if (ctx->backup_view != NULL &&
		   mail_index_lookup_seq(ctx->backup_view, uid, &old_seq)) {
		/* copy the metadata from backup index. */
		index_index_copy_from_old(ctx, ctx->backup_view,
					  old_seq, new_seq);
	}
}

static void
index_rebuild_header(struct index_rebuild_context *ctx,
		     index_rebuild_generate_uidvalidity_t *gen_uidvalidity)
{
	const struct mail_index_header *hdr, *backup_hdr, *trans_hdr;
	struct mail_index *index = mail_index_view_get_index(ctx->view);
	struct mail_index_modseq_header modseq_hdr;
	struct mail_index_view *trans_view;
	uint32_t uid_validity, next_uid, first_recent_uid;
	uint64_t modseq;

	hdr = mail_index_get_header(ctx->view);
	backup_hdr = ctx->backup_view == NULL ? NULL :
		mail_index_get_header(ctx->backup_view);
	trans_view = mail_index_transaction_open_updated_view(ctx->trans);
	trans_hdr = mail_index_get_header(trans_view);

	/* set uidvalidity */
	if (hdr->uid_validity != 0)
		uid_validity = hdr->uid_validity;
	else if (backup_hdr != NULL && backup_hdr->uid_validity != 0)
		uid_validity = backup_hdr->uid_validity;
	else
		uid_validity = gen_uidvalidity(ctx->box->list);
	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);

	/* set next-uid */
	if (hdr->next_uid != 0)
		next_uid = hdr->next_uid;
	else if (backup_hdr != NULL && backup_hdr->next_uid != 0)
		next_uid = backup_hdr->next_uid;
	else
		next_uid = 1;
	if (next_uid > trans_hdr->next_uid) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}

	/* set first_recent_uid */
	first_recent_uid = hdr->first_recent_uid;
	if (backup_hdr != NULL &&
	    backup_hdr->first_recent_uid > first_recent_uid &&
	    backup_hdr->first_recent_uid <= next_uid)
		first_recent_uid = backup_hdr->first_recent_uid;
	first_recent_uid = I_MIN(first_recent_uid, next_uid);
	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, first_recent_uid),
		&first_recent_uid, sizeof(first_recent_uid), FALSE);

	/* set highest-modseq */
	i_zero(&modseq_hdr);
	modseq_hdr.highest_modseq = mail_index_modseq_get_highest(ctx->view);
	if (ctx->backup_view != NULL) {
		modseq = mail_index_modseq_get_highest(ctx->backup_view);
		if (modseq_hdr.highest_modseq < modseq)
			modseq_hdr.highest_modseq = modseq;
	}
	mail_index_update_header_ext(ctx->trans, index->modseq_ext_id,
				     0, &modseq_hdr, sizeof(modseq_hdr));
	mail_index_view_close(&trans_view);
}

static void
index_rebuild_box_name_header(struct index_rebuild_context *ctx)
{
	const void *name_hdr;
	size_t name_hdr_size;

	mail_index_get_header_ext(ctx->view, ctx->box->box_name_hdr_ext_id,
				  &name_hdr, &name_hdr_size);
	if (name_hdr_size == 0 && ctx->backup_view != NULL) {
		mail_index_get_header_ext(ctx->backup_view,
					  ctx->box->box_name_hdr_ext_id,
					  &name_hdr, &name_hdr_size);
	}
	if (name_hdr_size == 0)
		return;
	mail_index_update_header_ext(ctx->trans, ctx->box->box_name_hdr_ext_id,
				     0, name_hdr, name_hdr_size);
}

struct index_rebuild_context *
index_index_rebuild_init(struct mailbox *box, struct mail_index_view *view,
			 struct mail_index_transaction *trans)
{
	struct index_rebuild_context *ctx;
	const char *index_dir, *backup_path;
	enum mail_index_open_flags open_flags = MAIL_INDEX_OPEN_FLAG_READONLY;

	ctx = i_new(struct index_rebuild_context, 1);
	ctx->box = box;
	ctx->view = view;
	ctx->trans = trans;
	mail_index_reset(ctx->trans);
	mailbox_recent_flags_reset(box);
	(void)mail_index_ext_lookup(box->index, "cache", &ctx->cache_ext_id);

	/* open cache and read the caching decisions. */
	(void)mail_cache_open_and_verify(ctx->box->cache);

	/* if backup index file exists, try to use it */
	index_dir = mailbox_get_index_path(box);
	backup_path = t_strconcat(box->index_prefix, ".backup", NULL);
	ctx->backup_index = mail_index_alloc(box->event,
					     index_dir, backup_path);

#ifndef MMAP_CONFLICTS_WRITE
	if (box->storage->set->mmap_disable)
#endif
		open_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	mail_index_set_lock_method(ctx->backup_index,
				   box->storage->set->parsed_lock_method,
				   UINT_MAX);
	if (mail_index_open(ctx->backup_index, open_flags) <= 0)
		mail_index_free(&ctx->backup_index);
	else
		ctx->backup_view = mail_index_view_open(ctx->backup_index);
	return ctx;
}

void index_index_rebuild_deinit(struct index_rebuild_context **_ctx,
				index_rebuild_generate_uidvalidity_t *cb)
{
	struct index_rebuild_context *ctx = *_ctx;

	*_ctx = NULL;

	/* initialize cache file with the old field decisions */
	(void)mail_cache_purge_with_trans(ctx->box->cache, ctx->trans,
					  (uint32_t)-1);
	index_rebuild_header(ctx, cb);
	index_rebuild_box_name_header(ctx);
	if (ctx->backup_index != NULL) {
		mail_index_view_close(&ctx->backup_view);
		mail_index_close(ctx->backup_index);
		mail_index_free(&ctx->backup_index);
	}
	i_free(ctx);
}
