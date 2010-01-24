/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
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

struct dbox_sync_rebuild_context *
dbox_sync_index_rebuild_init(struct index_mailbox *ibox,
			     struct mail_index_view *view,
			     struct mail_index_transaction *trans)
{
	struct mailbox *box = &ibox->box;
	struct dbox_sync_rebuild_context *ctx;
	const char *index_dir;
	enum mail_index_open_flags open_flags = MAIL_INDEX_OPEN_FLAG_READONLY;

	ctx = i_new(struct dbox_sync_rebuild_context, 1);
	ctx->ibox = ibox;
	ctx->view = view;
	ctx->trans = trans;
	mail_index_reset(ctx->trans);
	index_mailbox_reset_uidvalidity(ibox);
	mail_index_ext_lookup(ibox->index, "cache", &ctx->cache_ext_id);

	/* if backup index file exists, try to use it */
	index_dir = mailbox_list_get_path(box->list, box->name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	ctx->backup_index =
		mail_index_alloc(index_dir, DBOX_INDEX_PREFIX".backup");

#ifndef MMAP_CONFLICTS_WRITE
	if (box->storage->set->mmap_disable)
#endif
		open_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	if (mail_index_open(ctx->backup_index, open_flags,
			    box->storage->set->parsed_lock_method) <= 0)
		mail_index_free(&ctx->backup_index);
	else
		ctx->backup_view = mail_index_view_open(ctx->backup_index);
	return ctx;
}

void dbox_sync_index_rebuild_deinit(struct dbox_sync_rebuild_context **_ctx)
{
	struct dbox_sync_rebuild_context *ctx = *_ctx;

	*_ctx = NULL;
	if (ctx->backup_index != NULL) {
		mail_index_view_close(&ctx->backup_view);
		mail_index_free(&ctx->backup_index);
	}
	i_free(ctx);
}
