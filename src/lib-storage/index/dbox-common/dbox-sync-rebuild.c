/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-modseq.h"
#include "mailbox-list-private.h"
#include "index-storage.h"
#include "dbox-storage.h"
#include "dbox-sync-rebuild.h"

static void
dbox_sync_index_copy_cache(struct dbox_sync_rebuild_context *ctx,
			   struct mail_index_view *view,
			   uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index_map *map;
	const void *data;
	uint32_t reset_id;
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
dbox_sync_index_copy_from_old(struct dbox_sync_rebuild_context *ctx,
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

	dbox_sync_index_copy_cache(ctx, view, old_seq, new_seq);
}

void dbox_sync_rebuild_index_metadata(struct dbox_sync_rebuild_context *ctx,
				      uint32_t new_seq, uint32_t uid)
{
	uint32_t old_seq;

	if (mail_index_lookup_seq(ctx->view, uid, &old_seq)) {
		/* the message exists in the old index.
		   copy the metadata from it. */
		dbox_sync_index_copy_from_old(ctx, ctx->view, old_seq, new_seq);
	} else if (ctx->backup_view != NULL &&
		   mail_index_lookup_seq(ctx->backup_view, uid, &old_seq)) {
		/* copy the metadata from backup index. */
		dbox_sync_index_copy_from_old(ctx, ctx->backup_view,
					      old_seq, new_seq);
	}
}

static void dbox_sync_rebuild_header(struct dbox_sync_rebuild_context *ctx)
{
	const struct mail_index_header *hdr, *backup_hdr, *trans_hdr;
	struct mail_index *index = mail_index_view_get_index(ctx->view);
	struct mail_index_modseq_header modseq_hdr;
	struct mail_index_view *trans_view;
	uint32_t uid_validity, next_uid;
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
		uid_validity = dbox_get_uidvalidity_next(ctx->box->list);
	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);

	/* set next-uid */
	if (hdr->next_uid != 0)
		next_uid = hdr->next_uid;
	else if (backup_hdr != NULL && backup_hdr->next_uid != 0)
		next_uid = backup_hdr->next_uid;
	else
		next_uid = dbox_get_uidvalidity_next(ctx->box->list);
	if (next_uid > trans_hdr->next_uid) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}

	/* set highest-modseq */
	memset(&modseq_hdr, 0, sizeof(modseq_hdr));
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

struct dbox_sync_rebuild_context *
dbox_sync_index_rebuild_init(struct mailbox *box,
			     struct mail_index_view *view,
			     struct mail_index_transaction *trans)
{
	struct dbox_sync_rebuild_context *ctx;
	const char *index_dir;
	enum mail_index_open_flags open_flags = MAIL_INDEX_OPEN_FLAG_READONLY;

	ctx = i_new(struct dbox_sync_rebuild_context, 1);
	ctx->box = box;
	ctx->view = view;
	ctx->trans = trans;
	mail_index_reset(ctx->trans);
	index_mailbox_reset_uidvalidity(box);
	mail_index_ext_lookup(box->index, "cache", &ctx->cache_ext_id);

	/* if backup index file exists, try to use it */
	index_dir = mailbox_list_get_path(box->list, box->name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	ctx->backup_index =
		mail_index_alloc(index_dir, DBOX_INDEX_PREFIX".backup");

#ifndef MMAP_CONFLICTS_WRITE
	if (box->storage->set->mmap_disable)
#endif
		open_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	mail_index_set_lock_method(ctx->backup_index,
				   box->storage->set->parsed_lock_method, -1U);
	if (mail_index_open(ctx->backup_index, open_flags) <= 0)
		mail_index_free(&ctx->backup_index);
	else
		ctx->backup_view = mail_index_view_open(ctx->backup_index);
	return ctx;
}

void dbox_sync_index_rebuild_deinit(struct dbox_sync_rebuild_context **_ctx)
{
	struct dbox_sync_rebuild_context *ctx = *_ctx;

	*_ctx = NULL;
	dbox_sync_rebuild_header(ctx);
	if (ctx->backup_index != NULL) {
		mail_index_view_close(&ctx->backup_view);
		mail_index_close(ctx->backup_index);
		mail_index_free(&ctx->backup_index);
	}
	i_free(ctx);
}

int dbox_sync_rebuild_verify_alt_storage(struct mailbox_list *list)
{
	const char *alt_path;
	struct stat st;

	alt_path = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_ALT_DIR);
	if (alt_path == NULL)
		return 0;

	/* make sure alt storage is mounted. if it's not, abort the rebuild. */
	if (stat(alt_path, &st) == 0)
		return 0;
	if (errno != ENOENT) {
		i_error("stat(%s) failed: %m", alt_path);
		return -1;
	}

	/* try to create the alt directory. if it fails, it means alt
	   storage isn't mounted. */
	if (mailbox_list_mkdir(list, alt_path,
			       MAILBOX_LIST_PATH_TYPE_ALT_DIR) < 0)
		return -1;
	return 0;
}
