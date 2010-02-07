/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hash.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"

#define SDBOX_REBUILD_COUNT 3

static unsigned int sdbox_sync_file_entry_hash(const void *p)
{
	const struct sdbox_sync_file_entry *entry = p;

	return entry->uid;
}

static int sdbox_sync_file_entry_cmp(const void *p1, const void *p2)
{
	const struct sdbox_sync_file_entry *entry1 = p1, *entry2 = p2;

	/* this is only for hashing, don't bother ever returning 1. */
	if (entry1->uid != entry2->uid)
		return -1;
	return 0;
}

static int sdbox_sync_add_seq(struct sdbox_sync_context *ctx,
			      const struct mail_index_sync_rec *sync_rec,
			      uint32_t seq)
{
	struct sdbox_sync_file_entry *entry, lookup_entry;

	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE ||
		 sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	memset(&lookup_entry, 0, sizeof(lookup_entry));
	mail_index_lookup_uid(ctx->sync_view, seq, &lookup_entry.uid);

	entry = hash_table_lookup(ctx->syncs, &lookup_entry);
	if (entry == NULL) {
		entry = p_new(ctx->pool, struct sdbox_sync_file_entry, 1);
		*entry = lookup_entry;
		hash_table_insert(ctx->syncs, entry, entry);
	}

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE)
		entry->type = SDBOX_SYNC_ENTRY_TYPE_EXPUNGE;
	else if ((sync_rec->add_flags & SDBOX_INDEX_FLAG_ALT) != 0)
		entry->type = SDBOX_SYNC_ENTRY_TYPE_MOVE_TO_ALT;
	else
		entry->type = SDBOX_SYNC_ENTRY_TYPE_MOVE_FROM_ALT;
	return 1;
}

static int sdbox_sync_add(struct sdbox_sync_context *ctx,
			  const struct mail_index_sync_rec *sync_rec)
{
	uint32_t seq, seq1, seq2;
	int ret;

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		/* we're interested */
	} else if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS) {
		/* we care only about alt flag changes */
		if ((sync_rec->add_flags & SDBOX_INDEX_FLAG_ALT) == 0 &&
		    (sync_rec->remove_flags & SDBOX_INDEX_FLAG_ALT) == 0)
			return 1;
	} else {
		/* not interested */
		return 1;
	}

	if (!mail_index_lookup_seq_range(ctx->sync_view,
					 sync_rec->uid1, sync_rec->uid2,
					 &seq1, &seq2)) {
		/* already expunged everything. nothing to do. */
		return 1;
	}

	for (seq = seq1; seq <= seq2; seq++) {
		if ((ret = sdbox_sync_add_seq(ctx, sync_rec, seq)) <= 0)
			return ret;
	}
	return 1;
}

static int sdbox_sync_index(struct sdbox_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	const struct mail_index_header *hdr;
	struct mail_index_sync_rec sync_rec;
        struct hash_iterate_context *iter;
	void *key, *value;
	uint32_t seq1, seq2;
	int ret = 1;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity == 0) {
		/* newly created index file */
		return 0;
	}

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(ctx->sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2)) {
		index_mailbox_set_recent_seq(&ctx->mbox->ibox, ctx->sync_view,
					     seq1, seq2);
	}

	/* read all changes and group changes to same file_id together */
	ctx->pool = pool_alloconly_create("dbox sync pool", 1024*32);
	ctx->syncs = hash_table_create(default_pool, ctx->pool, 0,
				       sdbox_sync_file_entry_hash,
				       sdbox_sync_file_entry_cmp);

	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) {
		if ((ret = sdbox_sync_add(ctx, &sync_rec)) <= 0)
			break;
	}

	if (ret > 0) {
		/* now sync each file separately */
		iter = hash_table_iterate_init(ctx->syncs);
		while (hash_table_iterate(iter, &key, &value)) {
			const struct sdbox_sync_file_entry *entry = value;

			if ((ret = sdbox_sync_file(ctx, entry)) <= 0)
				break;
		}
		hash_table_iterate_deinit(&iter);
	}

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);

	hash_table_destroy(&ctx->syncs);
	pool_unref(&ctx->pool);
	return ret;
}

static int sdbox_refresh_header(struct sdbox_mailbox *mbox, bool retry)
{
	struct mail_index_view *view;
	struct sdbox_index_header hdr;
	int ret;

	view = mail_index_view_open(mbox->ibox.box.index);
	ret = sdbox_read_header(mbox, &hdr);
	mail_index_view_close(&view);

	if (ret == 0) {
		ret = mbox->sync_rebuild ? -1 : 0;
	} else if (retry) {
		(void)mail_index_refresh(mbox->ibox.box.index);
		return sdbox_refresh_header(mbox, FALSE);
	}
	return ret;
}

int sdbox_sync_begin(struct sdbox_mailbox *mbox, enum sdbox_sync_flags flags,
		     struct sdbox_sync_context **ctx_r)
{
	struct mail_storage *storage = mbox->ibox.box.storage;
	struct sdbox_sync_context *ctx;
	enum mail_index_sync_flags sync_flags = 0;
	unsigned int i;
	int ret;
	bool rebuild;

	rebuild = sdbox_refresh_header(mbox, TRUE) < 0 ||
		(flags & SDBOX_SYNC_FLAG_FORCE_REBUILD) != 0;

	ctx = i_new(struct sdbox_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flags = flags;

	if ((mbox->ibox.box.flags & MAILBOX_FLAG_KEEP_RECENT) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;
	if (!rebuild && (flags & SDBOX_SYNC_FLAG_FORCE) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
	if ((flags & SDBOX_SYNC_FLAG_FSYNC) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FSYNC;
	/* don't write unnecessary dirty flag updates */
	sync_flags |= MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;

	for (i = 0;; i++) {
		ret = mail_index_sync_begin(mbox->ibox.box.index,
					    &ctx->index_sync_ctx,
					    &ctx->sync_view, &ctx->trans,
					    sync_flags);
		if (ret <= 0) {
			if (ret < 0)
				mail_storage_set_index_error(&mbox->ibox.box);
			i_free(ctx);
			*ctx_r = NULL;
			return ret;
		}

		/* now that we're locked, check again if we want to rebuild */
		if (sdbox_refresh_header(mbox, FALSE) < 0)
			ret = 0;
		else {
			if ((ret = sdbox_sync_index(ctx)) > 0)
				break;
		}

		/* failure. keep the index locked while we're doing a
		   rebuild. */
		if (ret == 0) {
			if (i >= SDBOX_REBUILD_COUNT) {
				mail_storage_set_critical(storage,
					"dbox %s: Index keeps breaking",
					ctx->mbox->ibox.box.path);
				ret = -1;
			} else {
				/* do a full resync and try again. */
				i_warning("dbox %s: Rebuilding index",
					  ctx->mbox->ibox.box.path);
				ret = sdbox_sync_index_rebuild(mbox);
			}
		}
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		if (ret < 0) {
			i_free(ctx);
			return -1;
		}
	}

	*ctx_r = ctx;
	return 0;
}

int sdbox_sync_finish(struct sdbox_sync_context **_ctx, bool success)
{
	struct sdbox_sync_context *ctx = *_ctx;
	int ret = success ? 0 : -1;

	*_ctx = NULL;

	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox.box);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}
	if (ctx->path != NULL)
		str_free(&ctx->path);

	i_free(ctx);
	return ret;
}

int sdbox_sync(struct sdbox_mailbox *mbox, enum sdbox_sync_flags flags)
{
	struct sdbox_sync_context *sync_ctx;

	if (sdbox_sync_begin(mbox, flags, &sync_ctx) < 0)
		return -1;

	if (sync_ctx == NULL)
		return 0;
	return sdbox_sync_finish(&sync_ctx, TRUE);
}

struct mailbox_sync_context *
sdbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	enum sdbox_sync_flags sdbox_sync_flags = 0;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	if (ret == 0 && (index_mailbox_want_full_sync(&mbox->ibox, flags) ||
			 mbox->sync_rebuild)) {
		if ((flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0)
			sdbox_sync_flags |= SDBOX_SYNC_FLAG_FORCE_REBUILD;
		ret = sdbox_sync(mbox, sdbox_sync_flags);
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}
