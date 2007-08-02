/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "hex-dec.h"
#include "seq-range-array.h"
#include "dbox-storage.h"
#include "dbox-uidlist.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#include <stddef.h>

static int
dbox_sync_rec_get_uids(struct dbox_sync_context *ctx,
		       const struct dbox_sync_rec *sync_rec,
		       uint32_t *uid1_r, uint32_t *uid2_r)
{
	if (mail_index_lookup_uid(ctx->sync_view, sync_rec->seq1, uid1_r) < 0) {
		mail_storage_set_index_error(&ctx->mbox->ibox);
		return -1;
	}
	if (mail_index_lookup_uid(ctx->sync_view, sync_rec->seq2, uid2_r) < 0) {
		mail_storage_set_index_error(&ctx->mbox->ibox);
		return -1;
	}
	return 0;
}

static int
dbox_next_expunge(struct dbox_sync_context *ctx,
                  const struct dbox_sync_file_entry *sync_entry,
		  unsigned int *sync_idx, uint32_t *uid1_r, uint32_t *uid2_r)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	const struct dbox_sync_rec *sync_recs, *sync_rec;
	unsigned int count;
	uint32_t uid, seq;

	sync_recs = array_get(&sync_entry->sync_recs, &count);

	while (*sync_idx < count) {
		*sync_idx += 1;
		sync_rec = &sync_recs[*sync_idx];

		if (sync_rec->type != MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			continue;

		if (dbox_sync_rec_get_uids(ctx, sync_rec, uid1_r, uid2_r) < 0)
			return -1;

		if (box->v.sync_notify != NULL) {
			/* all of the UIDs uid1..uid2 should exist */
			for (uid = *uid1_r; uid <= *uid2_r; uid++) {
				box->v.sync_notify(box, uid,
						   MAILBOX_SYNC_TYPE_EXPUNGE);
			}
		}
		for (seq = sync_rec->seq1; seq != sync_rec->seq2; seq++)
			mail_index_expunge(ctx->trans, seq);

		return 1;
	}

	*uid1_r = *uid2_r = 0;
	return 0;
}

static int dbox_sync_expunge_copy(struct dbox_sync_context *ctx,
				  const struct dbox_sync_file_entry *sync_entry,
				  unsigned int sync_idx,
				  uint32_t first_nonexpunged_uid,
                                  const struct dbox_uidlist_entry *orig_entry,
				  uoff_t orig_offset)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	struct mail_storage *storage = &mbox->storage->storage;
	struct dotlock *dotlock;
	struct istream *input;
	struct ostream *output;
	struct dbox_file *file;
        struct dbox_uidlist_entry dest_entry;
	const struct dbox_sync_rec *sync_recs;
	const char *path, *lock_path;
	uint32_t file_seq, seq, uid1, uid2;
	unsigned int sync_count;
	int ret, fd;
	uoff_t full_size;
	off_t bytes;

	ret = dbox_file_seek(mbox, orig_entry->file_seq, orig_offset, FALSE);

	if (ret >= 0 && mbox->file->hdr.have_expunged_mails != '0') {
		/* there are some expunged mails in the file, go through all
		   of the mails. */
		ret = dbox_file_seek(mbox, orig_entry->file_seq,
				     mbox->file->header_size, FALSE);
	}

	/* skip mails until we find the first we don't want expunged */
	while (ret > 0) {
		ret = dbox_file_seek_next_nonexpunged(mbox);
		if (mbox->file->seeked_uid >= first_nonexpunged_uid)
			break;
	}

	if (ret <= 0) {
		if (ret == 0) {
			mail_storage_set_critical(storage,
				"%s: Expunging lost UID %u from file %u",
				mbox->path, first_nonexpunged_uid,
				orig_entry->file_seq);
		}
		return ret;
	}

	sync_recs = array_get(&sync_entry->sync_recs, &sync_count);
	if (sync_idx == sync_count)
		uid1 = uid2 = 0;
	else {
		if (dbox_sync_rec_get_uids(ctx, &sync_recs[sync_idx],
					   &uid1, &uid2) < 0)
			return -1;
	}

	file_seq = dbox_uidlist_get_new_file_seq(mbox->uidlist);

	for (;; file_seq++) {
		path = t_strdup_printf("%s/"DBOX_MAIL_FILE_FORMAT,
				       mbox->path, file_seq);
		fd = file_dotlock_open(&mbox->storage->new_file_dotlock_set,
				       path, DOTLOCK_CREATE_FLAG_NONBLOCK,
				       &dotlock);
		if (fd >= 0)
			break;

		if (errno != EAGAIN) {
			mail_storage_set_critical(storage,
				"file_dotlock_open(%s) failed: %m", path);
			return -1;
		}

		/* try again with another file name */
	}
	output = o_stream_create_fd_file(fd, 0, FALSE);
	lock_path = file_dotlock_get_lock_path(dotlock);

	memset(&dest_entry, 0, sizeof(dest_entry));
	t_array_init(&dest_entry.uid_list, array_count(&orig_entry->uid_list));
	dest_entry.file_seq = file_seq;

	/* write file header */
	file = i_new(struct dbox_file, 1);
	file->fd = -1;
	file->output = output;
	if (dbox_file_write_header(mbox, file) < 0)
		ret = -1;
	dbox_file_close(file);

	while (ret > 0) {
		/* update mail's location in index */
		uint32_t uid = mbox->file->seeked_uid;
		uint64_t hdr_offset = output->offset;

		if (mail_index_lookup_uid_range(ctx->sync_view, uid, uid,
						&seq, &seq) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			ret = -1;
			break;
		}

		if (seq == 0) {
			mail_storage_set_critical(storage,
				"Expunged UID %u reappeared in file %s",
				uid, path);
			mail_index_mark_corrupted(mbox->ibox.index);
			ret = -1;
			break;
		}

		mail_index_update_ext(ctx->trans, seq, mbox->dbox_file_ext_idx,
				      &file_seq, NULL);
		mail_index_update_ext(ctx->trans, seq,
				      mbox->dbox_offset_ext_idx,
				      &hdr_offset, NULL);

		/* copy the mail */
		full_size = mbox->file->mail_header_size +
			mbox->file->seeked_mail_size;
		input = i_stream_create_limit(mbox->file->input,
					      mbox->file->seeked_offset,
					      full_size);
		bytes = o_stream_send_istream(output, input);
		i_stream_destroy(&input);

		if (bytes < 0) {
			mail_storage_set_critical(storage,
				"o_stream_send_istream(%s) failed: %m",
				lock_path);
			ret = -1;
			break;
		}
		if ((uoff_t)bytes != full_size) {
			mail_storage_set_critical(storage,
				"o_stream_send_istream(%s) wrote only %"
				PRIuUOFF_T" of %"PRIuUOFF_T" bytes", lock_path,
				(uoff_t)bytes, full_size);
			ret = -1;
			break;
		}

		seq_range_array_add(&dest_entry.uid_list, 0,
				    mbox->file->seeked_uid);

		/* seek to next non-expunged mail */
		for (;;) {
			ret = dbox_file_seek_next_nonexpunged(mbox);
			if (ret <= 0)
				break;

			while (mbox->file->seeked_uid > uid2 && uid2 != 0) {
				ret = dbox_next_expunge(ctx, sync_entry,
							&sync_idx,
							&uid1, &uid2);
				if (ret <= 0)
					break;
			}
			if (ret <= 0) {
				if (ret == 0) {
					/* we want to keep copying */
					ret = 1;
				}
				break;
			}

			if (mbox->file->seeked_uid < uid1 || uid1 == 0)
				break;
		}
	}

	if (ret == 0) {
		struct dbox_file_header hdr;

		/* update append_offset in header */
		DEC2HEX(hdr.append_offset_hex, output->offset);

		o_stream_flush(output);
		if (pwrite_full(fd, hdr.append_offset_hex,
				sizeof(hdr.append_offset_hex),
				offsetof(struct dbox_file_header,
					 append_offset_hex)) < 0) {
			mail_storage_set_critical(storage,
				"pwrite_full(%s) failed: %m", lock_path);
			ret = -1;
		}
	}
	o_stream_destroy(&output);

	if (ret < 0) {
		file_dotlock_delete(&dotlock);
		return -1;
	} else {
		if (file_dotlock_replace(&dotlock, 0) < 0)
			return -1;

		/* new file created successfully. append it to uidlist. */
		dbox_uidlist_sync_append(ctx->uidlist_sync_ctx, &dest_entry);
		return 0;
	}
}

static int dbox_sync_expunge_file(struct dbox_sync_context *ctx,
				  const struct dbox_sync_file_entry *sync_entry,
				  unsigned int sync_idx)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	const struct dbox_sync_rec *sync_recs;
	struct dbox_uidlist_entry *entry;
        struct seq_range *range;
	const char *path;
	unsigned int i, count, sync_count;
	uint32_t file_seq, uid, exp_uid1, exp_uid2, first_expunged_uid;
	uoff_t offset;
	int ret;
	bool seen_expunges, skipped_expunges;

	sync_recs = array_get(&sync_entry->sync_recs, &sync_count);
	if (dbox_sync_get_file_offset(ctx, sync_recs[sync_idx].seq1,
				      &file_seq, &offset) < 0)
		return -1;
	i_assert(file_seq == sync_entry->file_seq);

	entry = dbox_uidlist_entry_lookup(mbox->uidlist, sync_entry->file_seq);
	if (entry == NULL) {
		/* file is already unlinked. just remove from index. */
		return 0;
	}

	if (dbox_sync_rec_get_uids(ctx, &sync_recs[sync_idx],
				   &exp_uid1, &exp_uid2) < 0)
		return -1;

	/* find the first non-expunged mail */
	first_expunged_uid = exp_uid1;
	seen_expunges = FALSE; skipped_expunges = FALSE; uid = 0;
	range = array_get_modifiable(&entry->uid_list, &count);
	for (i = 0; i < count; i++) {
		uid = range[i].seq1;

		if (!seen_expunges) {
			if (uid < first_expunged_uid) {
				/* range begins with non-expunged messages */
				uid = first_expunged_uid;
				skipped_expunges = TRUE;
			}
		}

		while (uid <= range[i].seq2) {
			if (uid < exp_uid1 || exp_uid1 == 0) {
				/* non-expunged mails exist in this file */
				break;
			}
			seen_expunges = TRUE;

			if (range[i].seq2 < exp_uid2) {
				/* fully used up this uid range */
				uid = range[i].seq2 + 1;
				break;
			}

			/* this sync_rec was fully used. look up the next.
			   range[] doesn't contain non-existing UIDs, so
			   exp_uid2+1 should exist in it. */
			if (uid <= exp_uid2)
				uid = exp_uid2 + 1;

			ret = dbox_next_expunge(ctx, sync_entry, &sync_idx,
						&exp_uid1, &exp_uid2);
			if (ret <= 0) {
				if (ret < 0)
					return -1;
				/* end of sync records */
				break;
			}
		}
		if (uid <= range[i].seq2) {
			/* non-expunged mails exist in this file */
			break;
		}
	}

	if (i != count) {
		/* mails expunged from the middle. have to copy everything
		   after the first expunged mail to new file. after copying
		   we'll truncate/unlink the old file. */
		if (dbox_sync_expunge_copy(ctx, sync_entry, sync_idx,
					   uid, entry, offset) < 0)
			return -1;
		i++;
	}

	if (!skipped_expunges) {
		/* all mails expunged from file, unlink it. */
		path = t_strdup_printf("%s/"DBOX_MAIL_FILE_FORMAT,
				       mbox->path, entry->file_seq);
		if (unlink(path) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"unlink(%s) failed: %m", path);
			return -1;
		}

		dbox_uidlist_sync_unlink(ctx->uidlist_sync_ctx,
					 entry->file_seq);
		return 0;
	}

	/* mails expunged from the end of file, ftruncate() it */
	ret = dbox_file_seek(mbox, entry->file_seq, offset, FALSE);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		/* unexpected EOF -> already truncated */
	} else {
		/* file can no longer be appended to */
		if (pwrite_full(mbox->file->fd, "00000000EFFFFFFF", 16,
				offsetof(struct dbox_file_header,
					 append_offset_hex)) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"pwrite_full(%s) failed: %m", mbox->path);
			return -1;
		}

		if (ftruncate(mbox->file->fd, offset) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"ftruncate(%s) failed: %m", mbox->file->path);
			return -1;
		}

		if (mbox->file->hdr.have_expunged_mails != '0') {
			/* all mails in the file are expunged now */
			if (pwrite_full(mbox->file->fd, "0", 1,
					offsetof(struct dbox_file_header,
						 have_expunged_mails)) < 0) {
				mail_storage_set_critical(
					&mbox->storage->storage,
					"pwrite_full(%s) failed: %m",
					mbox->path);
				return -1;
			}
		}
	}

	/* remove from uidlist entry */
	for (; i > 0; i--) {
		if (range[i-1].seq1 < first_expunged_uid)
			break;
	}
	array_delete(&entry->uid_list, i, count-i);
	if (i > 0 && range[i-1].seq2 >= first_expunged_uid)
		range[i-1].seq2 = first_expunged_uid-1;

	/* file can no longer be written to */
	entry->file_size = INT_MAX;

	dbox_uidlist_sync_set_modified(ctx->uidlist_sync_ctx);
	return 0;
}

static int
uidlist_entry_remove_uids(struct dbox_sync_context *ctx,
			  const struct dbox_sync_file_entry *sync_entry)
{
	struct dbox_uidlist_entry *entry;
	const struct dbox_sync_rec *recs;
	uint32_t uid;
	unsigned int i, count, seq;

	entry = dbox_uidlist_entry_lookup(ctx->mbox->uidlist,
					  sync_entry->file_seq);
	if (entry == NULL)
		return 0;

	recs = array_get(&sync_entry->sync_recs, &count);
	for (i = 0; i < count; i++) {
		if (recs[i].type != MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			continue;

		for (seq = recs[i].seq1; seq <= recs[i].seq2; seq++) {
			if (mail_index_lookup_uid(ctx->sync_view,
						  seq, &uid) < 0) {
				mail_storage_set_index_error(&ctx->mbox->ibox);
				return -1;
			}
			seq_range_array_remove(&entry->uid_list, uid);
		}
	}

	if (array_count(&entry->uid_list) == 0) {
		dbox_uidlist_sync_unlink(ctx->uidlist_sync_ctx,
					 entry->file_seq);
	}
	dbox_uidlist_sync_set_modified(ctx->uidlist_sync_ctx);
	return 0;
}

int dbox_sync_expunge(struct dbox_sync_context *ctx,
		      const struct dbox_sync_file_entry *sync_entry,
		      unsigned int sync_idx)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	const struct dbox_sync_rec *sync_rec;
	struct dotlock *dotlock;
	const char *path;
	int ret;

	if (ctx->dotlock_failed_file_seq != sync_entry->file_seq) {
		/* we need to have the file locked in case another process is
		   appending there already. */
		path = t_strdup_printf("%s/"DBOX_MAIL_FILE_FORMAT,
				       mbox->path, sync_entry->file_seq);
		ret = file_dotlock_create(&mbox->storage->new_file_dotlock_set,
					  path, DOTLOCK_CREATE_FLAG_NONBLOCK,
					  &dotlock);
		if (ret < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"file_dotlock_create(%s) failed: %m", path);
			return -1;
		}

		if (ret > 0) {
			/* locked - copy the non-expunged mails after the
			   expunged mail to new file */
			ret = dbox_sync_expunge_file(ctx, sync_entry, sync_idx);
			file_dotlock_delete(&dotlock);
			return ret < 0 ? -1 : 1;
		}

		/* remember that we failed, so we don't waste time trying to
		   lock the file multiple times within same sync. */
		ctx->dotlock_failed_file_seq = sync_entry->file_seq;
	}

	/* couldn't lock it, someone's appending. we have no other
	   choice but to just mark the mail expunged. otherwise we'd
	   deadlock (appending process waits for uidlist lock which
	   we have, we wait for file lock which append process has) */
	sync_rec = array_idx(&sync_entry->sync_recs, sync_idx);
	if (dbox_sync_update_flags(ctx, sync_rec) < 0)
		return -1;

	/* mark in the header that the file contains expunged messages */
	if (pwrite_full(mbox->file->fd, "1", 1,
			offsetof(struct dbox_file_header,
				 have_expunged_mails)) < 0) {
		mail_storage_set_critical(&mbox->storage->storage,
			"pwrite(%s) failed: %m", mbox->file->path);
		return -1;
	}

	/* remove UIDs from the uidlist entry */
	return uidlist_entry_remove_uids(ctx, sync_entry);
}
