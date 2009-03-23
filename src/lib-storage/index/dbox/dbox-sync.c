/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hash.h"
#include "dbox-storage.h"
#include "dbox-storage-rebuild.h"
#include "dbox-map.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#define DBOX_REBUILD_COUNT 3

static unsigned int dbox_sync_file_entry_hash(const void *p)
{
	const struct dbox_sync_file_entry *entry = p;

	if (entry->file_id != 0)
		return entry->file_id | 0x80000000;
	else
		return entry->uid;
}

static int dbox_sync_file_entry_cmp(const void *p1, const void *p2)
{
	const struct dbox_sync_file_entry *entry1 = p1, *entry2 = p2;

	/* this is only for hashing, don't bother ever returning 1. */
	if (entry1->file_id != entry2->file_id)
		return -1;
	if (entry1->uid != entry2->uid)
		return -1;
	return 0;
}

static int dbox_sync_add_seq(struct dbox_sync_context *ctx,
			     const struct mail_index_sync_rec *sync_rec,
			     uint32_t seq)
{
	struct dbox_sync_file_entry *entry, lookup_entry;
	uint32_t map_uid;
	uoff_t offset;
	int ret;

	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE ||
		 sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	memset(&lookup_entry, 0, sizeof(lookup_entry));
	if (dbox_mail_lookup(ctx->mbox, ctx->sync_view, seq, &map_uid) < 0)
		return 0;
	if (map_uid == 0)
		mail_index_lookup_uid(ctx->sync_view, seq, &lookup_entry.uid);
	else {
		ret = dbox_map_lookup(ctx->mbox->storage->map, map_uid,
				      &lookup_entry.file_id, &offset);
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			/* mailbox is locked while syncing, so if ret=0 the
			   message got expunged from storage before it was
			   expunged from mailbox. that shouldn't happen. */
			dbox_map_set_corrupted(ctx->mbox->storage->map,
				"unexpectedly lost map_uid=%u", map_uid);
			return 0;
		}
	}

	entry = hash_table_lookup(ctx->syncs, &lookup_entry);
	if (entry == NULL) {
		entry = p_new(ctx->pool, struct dbox_sync_file_entry, 1);
		*entry = lookup_entry;
		hash_table_insert(ctx->syncs, entry, entry);
	}

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		if (!array_is_created(&entry->expunge_map_uids)) {
			p_array_init(&entry->expunge_map_uids, ctx->pool,
				     lookup_entry.uid != 0 ? 1 : 3);
			p_array_init(&entry->expunge_seqs, ctx->pool,
				     lookup_entry.uid != 0 ? 1 : 3);
		}
		seq_range_array_add(&entry->expunge_seqs, 0, seq);
		seq_range_array_add(&entry->expunge_map_uids, 0, map_uid);
	} else {
		if ((sync_rec->add_flags & DBOX_INDEX_FLAG_ALT) != 0)
			entry->move_to_alt = TRUE;
		else
			entry->move_from_alt = TRUE;
	}
	return 1;
}

static int dbox_sync_add(struct dbox_sync_context *ctx,
			 const struct mail_index_sync_rec *sync_rec)
{
	uint32_t seq, seq1, seq2;
	int ret;

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		/* we're interested */
	} else if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS) {
		/* we care only about alt flag changes */
		if ((sync_rec->add_flags & DBOX_INDEX_FLAG_ALT) == 0 &&
		    (sync_rec->remove_flags & DBOX_INDEX_FLAG_ALT) == 0)
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
		if ((ret = dbox_sync_add_seq(ctx, sync_rec, seq)) <= 0)
			return ret;
	}
	return 1;
}

static int dbox_sync_index(struct dbox_sync_context *ctx)
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
				       dbox_sync_file_entry_hash,
				       dbox_sync_file_entry_cmp);

	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) {
		if ((ret = dbox_sync_add(ctx, &sync_rec)) <= 0)
			break;
	}

	if (ret > 0) {
		/* now sync each file separately */
		iter = hash_table_iterate_init(ctx->syncs);
		while (hash_table_iterate(iter, &key, &value)) {
			const struct dbox_sync_file_entry *entry = value;

			if ((ret = dbox_sync_file(ctx, entry)) <= 0)
				break;
		}
		hash_table_iterate_deinit(&iter);
	}

	if (ret > 0 && ctx->map_trans != NULL) {
		if (dbox_map_transaction_commit(&ctx->map_trans) < 0)
			ret = -1;
	}

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);

	hash_table_destroy(&ctx->syncs);
	pool_unref(&ctx->pool);
	return ret;
}

static int dbox_refresh_header(struct dbox_mailbox *mbox)
{
	const struct dbox_index_header *hdr;
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(mbox->ibox.view, mbox->dbox_hdr_ext_id,
				  &data, &data_size);
	if (data_size != sizeof(*hdr)) {
		/* data_size=0 means it's never been synced as dbox.
		   data_size=4 is for backwards compatibility */
		if (data_size != 0 && data_size != 4) {
			i_warning("dbox %s: Invalid dbox header size",
				  mbox->path);
		}
		return -1;
	}
	hdr = data;

	mbox->highest_maildir_uid = hdr->highest_maildir_uid;
	if (mbox->storage->sync_rebuild)
		return -1;
	return 0;
}

int dbox_sync_begin(struct dbox_mailbox *mbox, enum dbox_sync_flags flags,
		    struct dbox_sync_context **ctx_r)
{
	struct mail_storage *storage = mbox->ibox.box.storage;
	struct dbox_sync_context *ctx;
	enum mail_index_sync_flags sync_flags = 0;
	unsigned int i;
	int ret;
	bool rebuild, storage_rebuilt = FALSE;

	rebuild = dbox_refresh_header(mbox) < 0;
	if (rebuild) {
		if (dbox_storage_rebuild(mbox->storage) < 0)
			return -1;
		storage_rebuilt = TRUE;
	}

	ctx = i_new(struct dbox_sync_context, 1);
	ctx->mbox = mbox;

	if (!mbox->ibox.keep_recent)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;
	if (!rebuild && (flags & DBOX_SYNC_FLAG_FORCE) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
	if ((flags & DBOX_SYNC_FLAG_FSYNC) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FSYNC;
	/* don't write unnecessary dirty flag updates */
	sync_flags |= MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;

	for (i = 0;; i++) {
		ret = mail_index_sync_begin(mbox->ibox.index,
					    &ctx->index_sync_ctx,
					    &ctx->sync_view, &ctx->trans,
					    sync_flags);
		if (ret <= 0) {
			if (ret < 0)
				mail_storage_set_index_error(&mbox->ibox);
			i_free(ctx);
			*ctx_r = NULL;
			return ret;
		}

		/* now that we're locked, check again if we want to rebuild */
		if (dbox_refresh_header(mbox) < 0)
			ret = 0;
		else {
			if ((ret = dbox_sync_index(ctx)) > 0)
				break;
		}

		/* failure. keep the index locked while we're doing a
		   rebuild. */
		if (ret == 0) {
			if (!storage_rebuilt) {
				/* we'll need to rebuild storage too.
				   try again from the beginning. */
				mail_index_sync_rollback(&ctx->index_sync_ctx);
				i_free(ctx);
				return dbox_sync_begin(mbox, flags, ctx_r);
			}
			if (mbox->storage->have_multi_msgs) {
				mail_storage_set_critical(storage,
					"dbox %s: Storage keeps breaking",
					ctx->mbox->path);
				ret = -1;
			} else if (i >= DBOX_REBUILD_COUNT) {
				mail_storage_set_critical(storage,
					"dbox %s: Index keeps breaking",
					ctx->mbox->path);
				ret = -1;
			} else {
				/* do a full resync and try again. */
				i_warning("dbox %s: Rebuilding index",
					  ctx->mbox->path);
				ret = dbox_sync_index_rebuild(mbox);
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

int dbox_sync_finish(struct dbox_sync_context **_ctx, bool success)
{
	struct dbox_sync_context *ctx = *_ctx;
	int ret = success ? 0 : -1;

	*_ctx = NULL;

	if (ctx->map_trans != NULL)
		dbox_map_transaction_rollback(&ctx->map_trans);

	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
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

int dbox_sync(struct dbox_mailbox *mbox)
{
	struct dbox_sync_context *sync_ctx;

	if (dbox_sync_begin(mbox, 0, &sync_ctx) < 0)
		return -1;

	if (sync_ctx == NULL)
		return 0;
	return dbox_sync_finish(&sync_ctx, TRUE);
}

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;
	int ret = 0;

	if (!box->opened)
		index_storage_mailbox_open(&mbox->ibox);

	if (index_mailbox_want_full_sync(&mbox->ibox, flags) ||
	    mbox->storage->sync_rebuild)
		ret = dbox_sync(mbox);

	return index_mailbox_sync_init(box, flags, ret < 0);
}

void dbox_sync_cleanup(struct dbox_storage *storage)
{
	const ARRAY_TYPE(seq_range) *ref0_file_ids;
	struct dbox_file *file;
	struct seq_range_iter iter;
	unsigned int i = 0;
	uint32_t file_id;
	bool deleted;

	ref0_file_ids = dbox_map_get_zero_ref_files(storage->map);
	seq_range_array_iter_init(&iter, ref0_file_ids); i = 0;
	while (seq_range_array_iter_nth(&iter, i++, &file_id)) T_BEGIN {
		file = dbox_file_init_multi(storage, file_id);
		if (dbox_file_open_or_create(file, &deleted) > 0 && !deleted)
			(void)dbox_sync_file_cleanup(file);
		else
			dbox_map_remove_file_id(storage->map, file_id);
		dbox_file_unref(&file);
	} T_END;
}
