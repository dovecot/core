/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hash.h"
#include "dbox-file.h"
#include "dbox-sync.h"
#include "dbox-uidlist.h"
#include "dbox-storage.h"

#include <stddef.h>

int dbox_sync_get_file_offset(struct dbox_sync_context *ctx, uint32_t seq,
			      uint32_t *file_seq_r, uoff_t *offset_r)
{
	int ret;

	ret = dbox_file_lookup_offset(ctx->mbox, ctx->sync_view, seq,
				      file_seq_r, offset_r);
	if (ret <= 0) {
		if (ret == 0) {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
				"Unexpectedly lost seq %u in "
				"dbox file %s", seq, ctx->mbox->path);
		}
		return -1;
	}
	return 0;
}

static int dbox_sync_add_seq(struct dbox_sync_context *ctx, uint32_t seq,
                             const struct dbox_sync_rec *sync_rec)
{
        struct dbox_sync_file_entry *entry;
	uint32_t file_seq;
	uoff_t offset;

	if (dbox_sync_get_file_offset(ctx, seq, &file_seq, &offset) < 0)
		return -1;

	if (ctx->prev_file_seq == file_seq)
		return 0; /* already added in last sequence */
	ctx->prev_file_seq = file_seq;

	entry = hash_lookup(ctx->syncs, POINTER_CAST(file_seq));
	if (entry != NULL) {
		/* check if it's already added */
		const struct dbox_sync_rec *sync_recs;
		unsigned int count;

		sync_recs = array_get(&entry->sync_recs, &count);
		i_assert(count > 0);
		if (memcmp(&sync_recs[count-1],
			   sync_rec, sizeof(*sync_rec)) == 0)
			return 0; /* already added */
	} else {
		entry = p_new(ctx->pool, struct dbox_sync_file_entry, 1);
		entry->file_seq = file_seq;
		ARRAY_CREATE(&entry->sync_recs, ctx->pool,
			     struct dbox_sync_rec, 3);
		hash_insert(ctx->syncs, POINTER_CAST(file_seq), entry);
	}

	array_append(&entry->sync_recs, sync_rec, 1);
	return 0;
}

static int dbox_sync_add(struct dbox_sync_context *ctx,
			 const struct mail_index_sync_rec *sync_rec)
{
        struct dbox_sync_rec dbox_sync_rec;
	uint32_t seq, seq1, seq2;

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_APPEND) {
		/* don't care about appends */
		return 0;
	}

	if (mail_index_lookup_uid_range(ctx->sync_view,
					sync_rec->uid1, sync_rec->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0) {
		/* already expunged everything. nothing to do. */
		return 0;
	}

	/* convert to dbox_sync_rec, which takes a bit less space and has
	   sequences instead of UIDs. */
	memset(&dbox_sync_rec, 0, sizeof(dbox_sync_rec));
	dbox_sync_rec.type = sync_rec->type;
	dbox_sync_rec.seq1 = seq1;
	dbox_sync_rec.seq2 = seq2;
	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
		dbox_sync_rec.value.flags.add = sync_rec->add_flags;
		dbox_sync_rec.value.flags.remove = sync_rec->remove_flags;
		break;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
		dbox_sync_rec.value.keyword_idx = sync_rec->keyword_idx;
		break;
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
	case MAIL_INDEX_SYNC_TYPE_APPEND:
		break;
	}

	/* now, add the same sync_rec to each file_seq's entry */
	ctx->prev_file_seq = 0;
	for (seq = seq1; seq <= seq2; seq++) {
		if (dbox_sync_add_seq(ctx, seq, &dbox_sync_rec) < 0)
			return -1;
	}
	return 0;
}

static int dbox_sync_file(struct dbox_sync_context *ctx,
                          const struct dbox_sync_file_entry *entry)
{
	const struct dbox_sync_rec *sync_recs;
	unsigned int i, count;
	int ret;

	sync_recs = array_get(&entry->sync_recs, &count);
	for (i = 0; i < count; i++) {
		switch (sync_recs[i].type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			ret = dbox_sync_expunge(ctx, entry, i);
			if (ret > 0) {
				/* handled expunging by copying the file.
				   while at it, also wrote all the other sync
				   changes to the file. */
				return 0;
			}
			if (ret < 0)
				return -1;
			/* handled expunging by writing expunge flags */
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			/* FIXME */
			break;
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			i_unreached();
		}
	}
	return 0;
}

static int dbox_sync_index(struct dbox_mailbox *mbox)
{
	struct dbox_sync_context ctx;
	struct mail_index_sync_rec sync_rec;
        struct hash_iterate_context *iter;
	const struct mail_index_header *hdr;
	void *key, *value;
	uint32_t seq, uid_validity, next_uid;
	uoff_t offset;
	time_t mtime;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.mbox = mbox;

	/* always start index syncing before uidlist, so we don't get
	   deadlocks */
	ret = mail_index_sync_begin(mbox->ibox.index, &ctx.index_sync_ctx,
				    &ctx.sync_view, (uint32_t)-1, (uoff_t)-1,
				    !mbox->ibox.keep_recent, TRUE);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->ibox);
		return ret;
	}
	if (dbox_uidlist_sync_init(mbox->uidlist, &ctx.uidlist_sync_ctx) < 0) {
		mail_index_sync_rollback(ctx.index_sync_ctx);
		return -1;
	}

	ctx.trans = mail_index_transaction_begin(ctx.sync_view, FALSE, TRUE);

	/* read all changes and sort them to file_seq order */
	ctx.pool = pool_alloconly_create("dbox sync pool", 10240);
	ctx.syncs = hash_create(default_pool, ctx.pool, 0, NULL, NULL);
	while ((ret = mail_index_sync_next(ctx.index_sync_ctx,
					   &sync_rec)) > 0) {
		if (dbox_sync_add(&ctx, &sync_rec) < 0) {
			ret = -1;
			break;
		}
	}

	iter = hash_iterate_init(ctx.syncs);
	while (hash_iterate(iter, &key, &value)) {
                const struct dbox_sync_file_entry *entry = value;

		if (dbox_sync_file(&ctx, entry) < 0) {
			ret = -1;
			break;
		}
	}
	hash_iterate_deinit(iter);

	hash_destroy(ctx.syncs);
	pool_unref(ctx.pool);

	if (ret < 0) {
		mail_storage_set_index_error(&mbox->ibox);
		mail_index_sync_rollback(ctx.index_sync_ctx);
		dbox_uidlist_sync_rollback(ctx.uidlist_sync_ctx);
		return -1;
	}

	uid_validity = dbox_uidlist_sync_get_uid_validity(ctx.uidlist_sync_ctx);
	next_uid = dbox_uidlist_sync_get_next_uid(ctx.uidlist_sync_ctx);

	hdr = mail_index_get_header(ctx.sync_view);
	if (hdr->uid_validity != uid_validity) {
		mail_index_update_header(ctx.trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	if (hdr->next_uid != next_uid) {
		mail_index_update_header(ctx.trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), TRUE);
	}

	if (dbox_uidlist_sync_commit(ctx.uidlist_sync_ctx, &mtime) < 0) {
		mail_index_sync_rollback(ctx.index_sync_ctx);
		return -1;
	}

	if ((uint32_t)mtime != hdr->sync_stamp) {
		uint32_t sync_stamp = mtime;

		mail_index_update_header(ctx.trans,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp), TRUE);
	}

	if (mail_index_transaction_commit(ctx.trans, &seq, &offset) < 0) {
		mail_storage_set_index_error(&mbox->ibox);
		mail_index_sync_rollback(ctx.index_sync_ctx);
		return -1;
	}

	if (mail_index_sync_commit(ctx.index_sync_ctx) < 0) {
		mail_storage_set_index_error(&mbox->ibox);
		return -1;
	}
	return 0;
}

int dbox_sync(struct dbox_mailbox *mbox, int force)
{
	if (!force) {
		/* just sync index */
		return dbox_sync_index(mbox);
	}

	return -1;
}

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;
	int ret = 0;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    mbox->ibox.sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <=
	    ioloop_time)
		ret = dbox_sync(mbox, FALSE);

	return index_mailbox_sync_init(box, flags, ret < 0);
}

int dbox_sync_if_changed(struct dbox_mailbox *mbox)
{
	const struct mail_index_header *hdr;
	time_t mtime;

	hdr = mail_index_get_header(mbox->ibox.view);
	if (hdr->sync_stamp == 0)
		return 1;

	if (dbox_uidlist_get_mtime(mbox->uidlist, &mtime) < 0)
		return -1;

	return (uint32_t)mtime == hdr->sync_stamp;
}
