/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hash.h"
#include "dbox-storage.h"
#include "dbox-index.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#define DBOX_FLUSH_SECS_INTERACTIVE (4*60*60)
#define DBOX_FLUSH_SECS_CLOSE (4*60*60)
#define DBOX_FLUSH_SECS_IMMEDIATE (24*60*60)

#define DBOX_REBUILD_COUNT 3

static int dbox_sync_add_seq(struct dbox_sync_context *ctx,
			     const struct mail_index_sync_rec *sync_rec,
			     uint32_t seq)
{
	struct dbox_sync_file_entry *entry;
	uint32_t file_id;
	uoff_t offset;
	bool uid_file, add;

	if (!dbox_file_lookup(ctx->mbox, ctx->sync_view, seq,
			      &file_id, &offset))
		return -1;

	entry = hash_table_lookup(ctx->syncs, POINTER_CAST(file_id));
	if (entry == NULL) {
		if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE ||
		    ctx->flush_dirty_flags) {
			/* expunges / flushing dirty flags */
			add = TRUE;
		} else if (sync_rec->type != MAIL_INDEX_SYNC_TYPE_FLAGS) {
			/* keywords, not flushing dirty flags */
			add = FALSE;
		} else {
			/* add if we're moving from/to alternative storage
			   and we actually have an alt directory specified */
			add = ((sync_rec->add_flags | sync_rec->remove_flags) &
			       DBOX_INDEX_FLAG_ALT) != 0 &&
				ctx->mbox->alt_path != NULL;
		}

		if (!add) {
			mail_index_update_flags(ctx->trans, seq, MODIFY_ADD,
				(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
			return 0;
		}

		entry = p_new(ctx->pool, struct dbox_sync_file_entry, 1);
		entry->file_id = file_id;
		hash_table_insert(ctx->syncs, POINTER_CAST(file_id), entry);
	}
	uid_file = (file_id & DBOX_FILE_ID_FLAG_UID) != 0;

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		if (!array_is_created(&entry->expunges)) {
			p_array_init(&entry->expunges, ctx->pool,
				     uid_file ? 1 : 3);
			seq_range_array_add(&ctx->expunge_files, 0, file_id);
		}
		seq_range_array_add(&entry->expunges, 0, seq);
	} else {
		if (!array_is_created(&entry->changes)) {
			p_array_init(&entry->changes, ctx->pool,
				     uid_file ? 1 : 8);
		}
		seq_range_array_add(&entry->changes, 0, seq);
	}
	return 0;
}

static int dbox_sync_add(struct dbox_sync_context *ctx,
			 const struct mail_index_sync_rec *sync_rec)
{
	uint32_t seq, seq1, seq2;

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_APPEND) {
		/* don't care about appends */
		return 0;
	}

	/* we assume that anything else than appends are interactive changes */
	ctx->mbox->last_interactive_change = ioloop_time;

	if (!mail_index_lookup_seq_range(ctx->sync_view,
					 sync_rec->uid1, sync_rec->uid2,
					 &seq1, &seq2)) {
		/* already expunged everything. nothing to do. */
		return 0;
	}

	for (seq = seq1; seq <= seq2; seq++) {
		if (dbox_sync_add_seq(ctx, sync_rec, seq) < 0)
			return -1;
	}
	return 0;
}

static int
dbox_sync_lock_expunge_file(struct dbox_sync_context *ctx, unsigned int file_id)
{
	struct dbox_index_record *rec;
	enum dbox_index_file_lock_status lock_status;
	int ret;

	ret = dbox_index_try_lock_file(ctx->mbox->dbox_index, file_id,
				       &lock_status);
	if (ret < 0)
		return -1;

	rec = dbox_index_record_lookup(ctx->mbox->dbox_index, file_id);
	switch (lock_status) {
	case DBOX_INDEX_FILE_LOCKED:
		seq_range_array_add(&ctx->locked_files, 0, file_id);
		rec->status = DBOX_INDEX_FILE_STATUS_NONAPPENDABLE;
		break;
	case DBOX_INDEX_FILE_LOCK_NOT_NEEDED:
	case DBOX_INDEX_FILE_LOCK_UNLINKED:
		i_assert(rec == NULL ||
			 rec->status != DBOX_INDEX_FILE_STATUS_APPENDABLE);
		break;
	case DBOX_INDEX_FILE_LOCK_TRY_AGAIN:
		rec->expunges = TRUE;
		break;
	}
	return 0;
}

static int dbox_sync_lock_expunge_files(struct dbox_sync_context *ctx)
{
	const struct seq_range *range;
	unsigned int i, count, id;

	range = array_get(&ctx->expunge_files, &count);
	for (i = 0; i < count; i++) {
		for (id = range[i].seq1; id <= range[i].seq2; id++) {
			if (dbox_sync_lock_expunge_file(ctx, id) < 0)
				return -1;
		}
	}
	return 0;
}

static void dbox_sync_unlock_files(struct dbox_sync_context *ctx)
{
	const struct seq_range *range;
	unsigned int i, count, id;

	range = array_get(&ctx->locked_files, &count);
	for (i = 0; i < count; i++) {
		for (id = range[i].seq1; id <= range[i].seq2; id++)
			dbox_index_unlock_file(ctx->mbox->dbox_index, id);
	}
}

static void dbox_sync_update_header(struct dbox_sync_context *ctx)
{
	struct dbox_index_header hdr;
	const void *data;
	size_t data_size;

	if (!ctx->flush_dirty_flags) {
		/* write the header if it doesn't exist yet */
		mail_index_get_header_ext(ctx->mbox->ibox.view,
					  ctx->mbox->dbox_hdr_ext_id,
					  &data, &data_size);
		if (data_size != 0)
			return;
	}

	hdr.last_dirty_flush_stamp = ioloop_time;
	mail_index_update_header_ext(ctx->trans, ctx->mbox->dbox_hdr_ext_id, 0,
				     &hdr.last_dirty_flush_stamp,
				     sizeof(hdr.last_dirty_flush_stamp));
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

	/* read all changes and sort them to file_id order */
	ctx->pool = pool_alloconly_create("dbox sync pool", 1024*32);
	ctx->syncs = hash_table_create(default_pool, ctx->pool, 0, NULL, NULL);
	i_array_init(&ctx->expunge_files, 32);
	i_array_init(&ctx->locked_files, 32);

	for (;;) {
		if (!mail_index_sync_next(ctx->index_sync_ctx, &sync_rec))
			break;
		if (dbox_sync_add(ctx, &sync_rec) < 0) {
			ret = 0;
			break;
		}
	}
	if (ret > 0) {
		if (dbox_sync_lock_expunge_files(ctx) < 0)
			ret = -1;
	}
	array_free(&ctx->expunge_files);

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

	if (ret > 0)
		dbox_sync_update_header(ctx);

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);

	dbox_sync_unlock_files(ctx);
	array_free(&ctx->locked_files);
	hash_table_destroy(&ctx->syncs);
	pool_unref(&ctx->pool);
	return ret;
}

static int dbox_sync_want_flush_dirty(struct dbox_mailbox *mbox,
				      bool close_flush_dirty_flags)
{
	const struct dbox_index_header *hdr;
	const void *data;
	size_t data_size;

	if (mbox->last_interactive_change <
	    ioloop_time - DBOX_FLUSH_SECS_INTERACTIVE)
		return 1;

	mail_index_get_header_ext(mbox->ibox.view, mbox->dbox_hdr_ext_id,
				  &data, &data_size);
	if (data_size != sizeof(*hdr)) {
		/* data_size=0 means it's never been synced as dbox */
		if (data_size != 0) {
			i_warning("dbox %s: Invalid dbox header size",
				  mbox->path);
		}
		return -1;
	}
	hdr = data;

	if (!close_flush_dirty_flags) {
		if ((time_t)hdr->last_dirty_flush_stamp <
		    ioloop_time - DBOX_FLUSH_SECS_IMMEDIATE)
			return 1;
	} else {
		if ((time_t)hdr->last_dirty_flush_stamp <
		    ioloop_time - DBOX_FLUSH_SECS_CLOSE)
			return 1;
	}
	return 0;
}

int dbox_sync_begin(struct dbox_mailbox *mbox,
		    struct dbox_sync_context **ctx_r,
		    bool close_flush_dirty_flags, bool force)
{
	struct mail_storage *storage = mbox->ibox.box.storage;
	struct dbox_sync_context *ctx;
	enum mail_index_sync_flags sync_flags = 0;
	unsigned int i;
	int ret;
	bool rebuild = FALSE;

	ret = dbox_sync_want_flush_dirty(mbox, close_flush_dirty_flags);
	if (ret > 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY;
	else if (ret < 0)
		rebuild = TRUE;
	else {
		if (close_flush_dirty_flags) {
			/* no need to sync */
			*ctx_r = NULL;
			return 0;
		}
	}

	ctx = i_new(struct dbox_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flush_dirty_flags =
		(sync_flags & MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY) != 0;

	if (!mbox->ibox.keep_recent)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;
	if (!rebuild && !force)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
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

		if (rebuild && dbox_sync_want_flush_dirty(mbox, FALSE) >= 0) {
			/* another process rebuilt it already */
			rebuild = FALSE;
		}
		if (rebuild) {
			ret = 0;
			rebuild = FALSE;
		} else {
			if ((ret = dbox_sync_index(ctx)) > 0)
				break;
		}

		/* failure. keep the index locked while we're doing a
		   rebuild. */
		if (ret == 0) {
			if (i >= DBOX_REBUILD_COUNT) {
				mail_storage_set_critical(storage,
					"dbox %s: Index keeps breaking",
					ctx->mbox->path);
				ret = -1;
			} else {
				/* do a full resync and try again. */
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
	return 0;
}

int dbox_sync(struct dbox_mailbox *mbox, bool close_flush_dirty_flags)
{
	struct dbox_sync_context *sync_ctx;

	if (dbox_sync_begin(mbox, &sync_ctx,
			    close_flush_dirty_flags, FALSE) < 0)
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

	if (index_mailbox_want_full_sync(&mbox->ibox, flags))
		ret = dbox_sync(mbox, FALSE);

	return index_mailbox_sync_init(box, flags, ret < 0);
}
