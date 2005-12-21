/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "seq-range-array.h"
#include "dbox-storage.h"
#include "dbox-uidlist.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#include <stddef.h>

static const struct dotlock_settings new_file_dotlock_set = {
	NULL,
	NULL,

	30, 5, 5,

	NULL,
	NULL,

	FALSE
};

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
	const struct dbox_sync_rec *sync_recs;
	unsigned int count;

	sync_recs = array_get(&sync_entry->sync_recs, &count);

	while (*sync_idx < count) {
		*sync_idx += 1;

		if (sync_recs[*sync_idx].type != MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			continue;

		if (dbox_sync_rec_get_uids(ctx, &sync_recs[*sync_idx],
					   uid1_r, uid2_r) < 0)
			return -1;
		return 1;
	}

	*uid1_r = *uid2_r = 0;
	return 0;
}

static int dbox_sync_expunge_copy(struct dbox_sync_context *ctx,
				  const struct dbox_sync_file_entry *sync_entry,
				  unsigned int sync_idx,
				  uint32_t first_nonexpunged_uid,
                                  struct dbox_uidlist_entry *orig_entry,
				  uoff_t orig_offset)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	struct dotlock *dotlock;
	struct istream *input;
	struct ostream *output;
	struct dbox_file_header hdr;
        struct dbox_uidlist_entry dest_entry;
	const struct dbox_sync_rec *sync_recs;
	const char *path;
	uint32_t file_seq, seq, uid1, uid2;
	unsigned int sync_count;
	int ret, fd;

	ret = dbox_file_seek(mbox, orig_entry->file_seq, orig_offset);
	while (ret > 0) {
		ret = dbox_file_seek_next_nonexpunged(mbox);
		if (ret <= 0)
			break;

		if (mbox->file->seeked_uid >= first_nonexpunged_uid)
			break;
	}
	if (ret < 0)
		return -1;

	sync_recs = array_get(&sync_entry->sync_recs, &sync_count);
	if (sync_idx == sync_count)
		uid1 = uid2 = 0;
	else {
		if (dbox_sync_rec_get_uids(ctx, &sync_recs[sync_idx],
					   &uid1, &uid2) < 0)
			return -1;
	}

	file_seq = dbox_uidlist_get_new_file_seq(mbox->uidlist);

	path = t_strdup_printf("%s/"DBOX_MAILDIR_NAME"/msg.%u",
			       mbox->path, file_seq);
	fd = file_dotlock_open(&new_file_dotlock_set, path, 0, &dotlock);
	output = o_stream_create_file(fd, default_pool, 0, FALSE);

	memset(&dest_entry, 0, sizeof(dest_entry));
	ARRAY_CREATE(&dest_entry.uid_list, pool_datastack_create(),
		     struct seq_range, array_count(&orig_entry->uid_list));
	dest_entry.file_seq = file_seq;

	/* write file header */
	dbox_file_header_init(&hdr);
	ret = o_stream_send(output, &hdr, sizeof(hdr));

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
			mail_storage_set_critical(STORAGE(mbox->storage),
				"Expunged UID %u reappeared in file %s",
				uid, path);
			ret = -1;
			break;
		}

		mail_index_update_ext(ctx->trans, seq, mbox->dbox_file_ext_idx,
				      &file_seq, NULL);
		mail_index_update_ext(ctx->trans, seq,
				      mbox->dbox_offset_ext_idx,
				      &hdr_offset, NULL);

		/* copy the mail */
		input = i_stream_create_limit(default_pool, mbox->file->input,
					      mbox->file->seeked_offset,
					      mbox->file->mail_header_size +
					      mbox->file->seeked_mail_size);
		ret = o_stream_send_istream(output, input);
		i_stream_unref(input);

		if (ret < 0) {
			mail_storage_set_critical(STORAGE(mbox->storage),
				"o_stream_send_istream(%s) failed: %m", path);
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
			if (ret <= 0)
				break;

			if (mbox->file->seeked_uid < uid1 || uid1 == 0)
				break;
		}
	}
	o_stream_unref(output);

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
	unsigned int i, count, sync_count;
	uint32_t file_seq, uid, uid1, uid2, first_expunged_uid;
	uoff_t offset;
	int ret, seen_expunges, skipped_expunges;

	sync_recs = array_get(&sync_entry->sync_recs, &sync_count);
	if (dbox_sync_get_file_offset(ctx, sync_recs[sync_idx].seq1,
				      &file_seq, &offset) < 0)
		return -1;

	entry = dbox_uidlist_entry_lookup(mbox->uidlist, sync_entry->file_seq);
	if (entry == NULL) {
		/* file is already unlinked. just remove from index. */
		return 0;
	}

	if (dbox_sync_rec_get_uids(ctx, &sync_recs[sync_idx], &uid1, &uid2) < 0)
		return -1;

	/* find the first non-expunged mail */
	first_expunged_uid = uid1;
	seen_expunges = FALSE; skipped_expunges = FALSE; uid = 0;
	range = array_get_modifyable(&entry->uid_list, &count);
	for (i = 0; i < count; i++) {
		uid = range[i].seq1;

		if (!seen_expunges) {
			if (uid != first_expunged_uid) {
				/* range begins with non-expunged messages */
				i_assert(uid < first_expunged_uid);
				uid = first_expunged_uid;
				skipped_expunges = TRUE;
			}
		}

		while (uid <= range[i].seq2) {
			if (uid < uid1) {
				/* non-expunged mails exist in this file */
				break;
			}
			seen_expunges = TRUE;

			if (range[i].seq2 < uid2) {
				/* fully used up this uid range */
				uid = range[i].seq2 + 1;
				break;
			}

			/* this sync_rec was fully used. look up the next.
			   range[] doesn't contain non-existing UIDs, so
			   uid2+1 should exist in it. */
			uid = uid2 + 1;

			ret = dbox_next_expunge(ctx, sync_entry, &sync_idx,
						&uid1, &uid2);
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
		return dbox_uidlist_sync_unlink(ctx->uidlist_sync_ctx,
						entry->file_seq);
	}

	/* mails expunged from the end of file, ftruncate() it */

	ret = dbox_file_seek(mbox, entry->file_seq, offset);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		/* unexpected EOF -> already truncated */
	} else {
		if (ftruncate(mbox->file->fd, offset) < 0) {
			mail_storage_set_critical(STORAGE(mbox->storage),
				"ftruncate(%s) failed: %m", mbox->path);
			return -1;
		}
	}

	/* remove from uidlist entry */
	for (; i > 0; i--) {
		if (range[i-1].seq1 < first_expunged_uid)
			break;
	}
	array_delete(&entry->uid_list, i, count-i);
	if (i > 0)
		range[i-1].seq2 = first_expunged_uid-1;

	dbox_uidlist_sync_set_modified(ctx->uidlist_sync_ctx);
	return 0;
}

int dbox_sync_expunge(struct dbox_sync_context *ctx,
		      const struct dbox_sync_file_entry *entry,
		      unsigned int sync_idx)
{
	const struct dbox_sync_rec *sync_rec;
	struct dotlock *dotlock;
	const char *path;
	int ret;

	if (ctx->dotlock_failed_file_seq != entry->file_seq) {
		/* we need to have the file locked in case another process is
		   appending there already. */
		path = t_strdup_printf("%s/"DBOX_MAILDIR_NAME"/msg.%u",
				       ctx->mbox->path, entry->file_seq);
		ret = file_dotlock_create(&new_file_dotlock_set, path,
					  DOTLOCK_CREATE_FLAG_NONBLOCK,
					  &dotlock);
		if (ret < 0)
			return -1;

		if (ret > 0) {
			/* locked - copy the non-expunged mails after the
			   expunged mail to new file */
			ret = dbox_sync_expunge_file(ctx, entry, sync_idx);
			file_dotlock_delete(&dotlock);
			return ret < 0 ? -1 : 1;
		}

		/* remember that we failed, so we don't waste time trying to
		   lock the file multiple times within same sync. */
		ctx->dotlock_failed_file_seq = entry->file_seq;
	}

	/* couldn't lock it, someone's appending. we have no other
	   choice but to just mark the mail expunged. otherwise we'd
	   deadlock (appending process waits for uidlist lock which
	   we have, we wait for file lock which append process has) */
	sync_rec = array_idx(&entry->sync_recs, sync_idx);
	return dbox_sync_update_flags(ctx, sync_rec);
}
