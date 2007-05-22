/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hash.h"
#include "seq-range-array.h"
#include "write-full.h"
#include "dbox-file.h"
#include "dbox-keywords.h"
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
			mail_storage_set_critical(&ctx->mbox->storage->storage,
				"Unexpectedly lost seq %u in "
				"dbox %s", seq, ctx->mbox->path);
		}
		return -1;
	}
	if (*file_seq_r == 0) {
		mail_storage_set_critical(&ctx->mbox->storage->storage,
			"Cached message offset lost for seq %u in "
			"dbox %s", seq, ctx->mbox->path);
		return -1;
	}
	return 0;
}

static int dbox_sync_add_seq(struct dbox_sync_context *ctx, uint32_t seq,
                             const struct dbox_sync_rec *sync_rec)
{
	struct dbox_sync_rec new_sync_rec;
	struct dbox_sync_file_entry *entry;
	const uint32_t *file_seqs;
	unsigned int i, count;
	uint32_t file_seq;
	uoff_t offset;

	if (dbox_sync_get_file_offset(ctx, seq, &file_seq, &offset) < 0)
		return -1;

	file_seqs = array_get(&ctx->added_file_seqs, &count);
	for (i = 0; i < count; i++) {
		if (file_seqs[i] == file_seq) {
			/* already added */
			return 0;
		}
	}
	array_append(&ctx->added_file_seqs, &file_seq, 1);

	entry = hash_lookup(ctx->syncs, POINTER_CAST(file_seq));
	if (entry == NULL) {
		entry = p_new(ctx->pool, struct dbox_sync_file_entry, 1);
		entry->file_seq = file_seq;
		p_array_init(&entry->sync_recs, ctx->pool, 3);
		hash_insert(ctx->syncs, POINTER_CAST(file_seq), entry);
	}

	new_sync_rec = *sync_rec;
	new_sync_rec.seq1 = seq;
	array_append(&entry->sync_recs, &new_sync_rec, 1);
	return 0;
}

static int dbox_update_recent_flags(struct dbox_sync_context *ctx,
				    uint32_t seq1, uint32_t seq2)
{
	uint32_t seq;
	const struct mail_index_record *rec;

	for (seq = seq1; seq <= seq2; seq++) {
		if (mail_index_lookup(ctx->sync_view, seq, &rec) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			return -1;
		}
		if ((rec->flags & MAIL_RECENT) != 0)
			index_mailbox_set_recent(&ctx->mbox->ibox, seq);
	}
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
					&seq1, &seq2) < 0) {
		mail_storage_set_index_error(&ctx->mbox->ibox);
		return -1;
	}

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
		if ((sync_rec->remove_flags & MAIL_RECENT) != 0) {
			if (dbox_update_recent_flags(ctx, seq1, seq2) < 0)
				return -1;
		}
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
	array_clear(&ctx->added_file_seqs);
	for (seq = seq1; seq <= seq2; seq++) {
		if (dbox_sync_add_seq(ctx, seq, &dbox_sync_rec) < 0)
			return -1;
	}
	return 0;
}

static int
dbox_sync_write_mask(struct dbox_sync_context *ctx,
		     const struct dbox_sync_rec *sync_rec,
                     unsigned int first_flag_offset, unsigned int flag_count,
		     const unsigned char *array, const unsigned char *mask)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	struct mailbox *box = &mbox->ibox.box;
	enum mailbox_sync_type sync_type;
	uint32_t file_seq, uid2;
	uoff_t offset;
	unsigned int i, start;
	int ret;

	if (dbox_sync_get_file_offset(ctx, sync_rec->seq1,
				      &file_seq, &offset) < 0)
		return -1;

	if (mail_index_lookup_uid(ctx->sync_view, sync_rec->seq2, &uid2) < 0) {
		mail_storage_set_index_error(&mbox->ibox);
		return -1;
	}

	if ((ret = dbox_file_seek(mbox, file_seq, offset, FALSE)) <= 0)
		return ret;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
		sync_type = MAILBOX_SYNC_TYPE_EXPUNGE;
		break;
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
		sync_type = MAILBOX_SYNC_TYPE_FLAGS;
		break;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
		sync_type = MAILBOX_SYNC_TYPE_KEYWORDS;
		break;
	default:
		sync_type = 0;
		i_unreached();
	}
	while (mbox->file->seeked_uid <= uid2) {
		if (box->v.sync_notify != NULL) {
			box->v.sync_notify(box, mbox->file->seeked_uid,
					   sync_type);
		}
		for (i = 0; i < flag_count; ) {
			if (!mask[i]) {
				i++;
				continue;
			}

			start = i;
			while (i < flag_count) {
				if (!mask[i])
					break;
				i++;
			}
			ret = pwrite_full(mbox->file->fd,
					  array + start, i - start,
					  offset + first_flag_offset + start);
			if (ret < 0) {
				mail_storage_set_critical(
					&mbox->storage->storage,
					"pwrite(%s) failed: %m",
					mbox->file->path);
				return -1;
			}
		}

		ret = dbox_file_seek_next_nonexpunged(mbox);
		if (ret <= 0) {
			if (ret == 0)
				break;
			return -1;
		}
		offset = mbox->file->seeked_offset;
	}
	return 0;
}

int dbox_sync_update_flags(struct dbox_sync_context *ctx,
			   const struct dbox_sync_rec *sync_rec)
{
	static enum mail_flags dbox_flag_list[] = {
		MAIL_ANSWERED,
		MAIL_FLAGGED,
		MAIL_DELETED,
		MAIL_SEEN,
		MAIL_DRAFT
	};
#define DBOX_FLAG_COUNT (sizeof(dbox_flag_list)/sizeof(dbox_flag_list[0]))
	unsigned char dbox_flag_array[DBOX_FLAG_COUNT];
	unsigned char dbox_flag_mask[DBOX_FLAG_COUNT];
	unsigned int i, first_flag_offset;

	/* first build flag array and mask */
	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		dbox_flag_array[0] = '1';
		dbox_flag_mask[0] = 1;

		first_flag_offset = offsetof(struct dbox_mail_header, expunged);
		return dbox_sync_write_mask(ctx, sync_rec,
					    first_flag_offset, 1,
					    dbox_flag_array, dbox_flag_mask);
	} else {
		i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);
		for (i = 0; i < DBOX_FLAG_COUNT; i++) {
			dbox_flag_array[i] =
				(sync_rec->value.flags.add &
				 dbox_flag_list[i]) != 0 ? '1' : '0';
			dbox_flag_mask[i] =
				((sync_rec->value.flags.remove |
				  sync_rec->value.flags.add) &
				 dbox_flag_list[i]) != 0;
		}

		first_flag_offset = offsetof(struct dbox_mail_header, answered);
		return dbox_sync_write_mask(ctx, sync_rec,
					    first_flag_offset,
					    DBOX_FLAG_COUNT,
					    dbox_flag_array, dbox_flag_mask);
	}
}

static int
dbox_sync_update_keyword(struct dbox_sync_context *ctx,
			 const struct dbox_sync_file_entry *entry,
			 const struct dbox_sync_rec *sync_rec, bool set)
{
	unsigned char keyword_array, keyword_mask = 1;
	unsigned int file_idx, first_flag_offset;

	if (dbox_file_seek(ctx->mbox, entry->file_seq, 0, FALSE) <= 0)
		return -1;

	keyword_array = set ? '1' : '0';

	if (!dbox_file_lookup_keyword(ctx->mbox, ctx->mbox->file,
				      sync_rec->value.keyword_idx, &file_idx)) {
		/* not found. if removing, just ignore.

		   if adding, it currently happens only if the maximum keyword
		   count was reached. once we support moving mails to new file
		   to grow keywords count, this should never happen.
		   for now, just ignore this. */
		return 0;
	}

	first_flag_offset = sizeof(struct dbox_mail_header) + file_idx;
	return dbox_sync_write_mask(ctx, sync_rec, first_flag_offset, 1,
				    &keyword_array, &keyword_mask);
}

static int
dbox_sync_reset_keyword(struct dbox_sync_context *ctx,
			const struct dbox_sync_file_entry *entry,
			const struct dbox_sync_rec *sync_rec)
{
	unsigned char *keyword_array, *keyword_mask;
	unsigned int first_flag_offset;
	int ret;

	if (dbox_file_seek(ctx->mbox, entry->file_seq, 0, FALSE) <= 0)
		return -1;

	if (ctx->mbox->file->keyword_count == 0)
		return 0;

	t_push();
	keyword_array = t_malloc(ctx->mbox->file->keyword_count);
	keyword_mask = t_malloc(ctx->mbox->file->keyword_count);
	memset(keyword_array, '0', ctx->mbox->file->keyword_count);
	memset(keyword_mask, 1, ctx->mbox->file->keyword_count);

	first_flag_offset = sizeof(struct dbox_mail_header);
	ret = dbox_sync_write_mask(ctx, sync_rec, first_flag_offset,
				   ctx->mbox->file->keyword_count,
				   keyword_array, keyword_mask);
	t_pop();
	return ret;
}

static int
dbox_sync_file_add_keywords(struct dbox_sync_context *ctx,
			    const struct dbox_sync_file_entry *entry,
			    unsigned int i)
{
	ARRAY_TYPE(seq_range) keywords;
	const struct dbox_sync_rec *sync_recs;
	const struct seq_range *range;
	unsigned int count, file_idx, keyword_idx;
	int ret = 0;

	if (dbox_file_seek(ctx->mbox, entry->file_seq, 0, FALSE) <= 0)
		return -1;

	/* Get a list of all new keywords. Using seq_range is the easiest
	   way to do this and should be pretty fast too. */
	t_push();
	t_array_init(&keywords, 16);
	sync_recs = array_get(&entry->sync_recs, &count);
	for (; i < count; i++) {
		if (sync_recs[i].type != MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD)
			continue;

		/* check if it's already in the file */
                keyword_idx = sync_recs[i].value.keyword_idx;
		if (dbox_file_lookup_keyword(ctx->mbox, ctx->mbox->file,
					     keyword_idx, &file_idx))
			continue;

		/* add it. if it already exists, it's handled internally. */
		seq_range_array_add(&keywords, 0, keyword_idx);
	}

	/* now, write them to file */
	range = array_get(&keywords, &count);
	if (count > 0) {
		ret = dbox_file_append_keywords(ctx->mbox, ctx->mbox->file,
						range, count);
	}

	t_pop();
	return ret;
}

static int dbox_sync_file(struct dbox_sync_context *ctx,
                          const struct dbox_sync_file_entry *entry)
{
	const struct dbox_sync_rec *sync_recs;
	unsigned int i, count;
	bool first_keyword = TRUE;
	int ret;

	sync_recs = array_get(&entry->sync_recs, &count);
	for (i = 0; i < count; i++) {
		switch (sync_recs[i].type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			t_push();
			ret = dbox_sync_expunge(ctx, entry, i);
			t_pop();
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
			if (dbox_sync_update_flags(ctx, &sync_recs[i]) < 0)
				return -1;
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
			if (first_keyword) {
				/* add all new keywords in one go */
				first_keyword = FALSE;
				if (dbox_sync_file_add_keywords(ctx, entry,
								i) < 0)
					return -1;
			}
			if (dbox_sync_update_keyword(ctx, entry, &sync_recs[i],
						     TRUE) < 0)
				return -1;
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			if (dbox_sync_update_keyword(ctx, entry, &sync_recs[i],
						     FALSE) < 0)
				return -1;
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			if (dbox_sync_reset_keyword(ctx, entry,
						    &sync_recs[i]) < 0)
				return -1;
			break;
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			i_unreached();
		}
	}
	return 0;
}

static int dbox_sync_index(struct dbox_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	struct mail_index_sync_rec sync_rec;
        struct hash_iterate_context *iter;
	void *key, *value;
	int ret;

	/* read all changes and sort them to file_seq order */
	ctx->pool = pool_alloconly_create("dbox sync pool", 10240);
	ctx->syncs = hash_create(default_pool, ctx->pool, 0, NULL, NULL);
	i_array_init(&ctx->added_file_seqs, 64);
	for (;;) {
		ret = mail_index_sync_next(ctx->index_sync_ctx, &sync_rec);
		if (ret <= 0) {
			if (ret < 0)
				mail_storage_set_index_error(&ctx->mbox->ibox);
			break;
		}
		if (dbox_sync_add(ctx, &sync_rec) < 0) {
			ret = -1;
			break;
		}
	}
	array_free(&ctx->added_file_seqs);

	iter = hash_iterate_init(ctx->syncs);
	while (hash_iterate(iter, &key, &value)) {
                const struct dbox_sync_file_entry *entry = value;

		if (dbox_sync_file(ctx, entry) < 0) {
			ret = -1;
			break;
		}
	}
	hash_iterate_deinit(iter);

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);

	hash_destroy(ctx->syncs);
	pool_unref(ctx->pool);

	return ret;
}

static int dbox_sync_init(struct dbox_mailbox *mbox,
			  struct dbox_sync_context *ctx, bool *force)
{
	const struct mail_index_header *hdr;
	time_t mtime;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->mbox = mbox;

	/* uidlist locking is done before index locking. */
	if (dbox_uidlist_sync_init(mbox->uidlist, &ctx->uidlist_sync_ctx,
				   &mtime) < 0)
		return -1;

	ret = mail_index_sync_begin(mbox->ibox.index, &ctx->index_sync_ctx,
				    &ctx->sync_view, &ctx->trans,
				    (uint32_t)-1, (uoff_t)-1,
				    !mbox->ibox.keep_recent, TRUE);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->ibox);
		dbox_uidlist_sync_rollback(ctx->uidlist_sync_ctx);
		return ret;
	}

	hdr = mail_index_get_header(ctx->sync_view);
	if ((uint32_t)mtime != hdr->sync_stamp) {
		/* indexes aren't synced. we'll do a full sync. */
		*force = TRUE;
	}
	return 1;
}

static int dbox_sync_finish(struct dbox_sync_context *ctx, bool force)
{
	const struct mail_index_header *hdr;
	uint32_t uid_validity, next_uid;
	time_t mtime;
	int ret;

	if (force)
		ret = dbox_sync_full(ctx);
	else
		ret = dbox_sync_index(ctx);

	if (ret < 0) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		dbox_uidlist_sync_rollback(ctx->uidlist_sync_ctx);
		return -1;
	}

	uid_validity = dbox_uidlist_sync_get_uid_validity(ctx->uidlist_sync_ctx);
	next_uid = dbox_uidlist_sync_get_next_uid(ctx->uidlist_sync_ctx);

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity != uid_validity) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	if (hdr->next_uid != next_uid) {
		i_assert(next_uid > hdr->next_uid ||
			 hdr->uid_validity != uid_validity);
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}

	if (dbox_uidlist_sync_commit(ctx->uidlist_sync_ctx, &mtime) < 0) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		return -1;
	}

	if ((uint32_t)mtime != hdr->sync_stamp) {
		uint32_t sync_stamp = mtime;

		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp), TRUE);
	}

	if (force) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	} else {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			return -1;
		}
	}
	return 0;
}

static int dbox_sync_int(struct dbox_mailbox *mbox, bool force)
{
	struct dbox_sync_context ctx;
	int ret;

	if ((ret = dbox_sync_init(mbox, &ctx, &force)) <= 0)
		return ret;

	if ((ret = dbox_sync_finish(&ctx, force)) < 0)
		return ret;

	if (force) {
		/* now that indexes are ok, sync changes from the index */
		force = FALSE;
		if ((ret = dbox_sync_init(mbox, &ctx, &force)) <= 0)
			return ret;

		if (force) {
			mail_storage_set_critical(&mbox->storage->storage,
				"dbox_sync_full(%s) didn't work",
				mbox->path);

			mail_index_sync_rollback(&ctx.index_sync_ctx);
			dbox_uidlist_sync_rollback(ctx.uidlist_sync_ctx);
			return -1;
		}
		return dbox_sync_finish(&ctx, FALSE);
	} else {
		return 0;
	}
}

int dbox_sync(struct dbox_mailbox *mbox, bool force)
{
	int ret;

	mbox->syncing = TRUE;
	ret = dbox_sync_int(mbox, force);
	mbox->syncing = FALSE;
	return ret;
}

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;
	int ret = 0;

	if (!box->opened)
		index_storage_mailbox_open(&mbox->ibox);

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    mbox->ibox.sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <=
	    ioloop_time)
		ret = dbox_sync(mbox, FALSE);

	return index_mailbox_sync_init(box, flags, ret < 0);
}

int dbox_sync_is_changed(struct dbox_mailbox *mbox)
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
