/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "dbox-storage.h"
#include "dbox-uidlist.h"
#include "dbox-file.h"
#include "dbox-keywords.h"
#include "dbox-sync.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

static int
dbox_mail_get_keywords(struct dbox_mailbox *mbox, struct dbox_file *file,
		       ARRAY_TYPE(keyword_indexes) *keywords)
{
	const unsigned int *map;
	unsigned int i, count;

	if (!array_is_created(&file->file_idx_keywords)) {
		if (dbox_file_read_keywords(mbox, file) < 0)
			return -1;
	}

	map = array_get(&file->file_idx_keywords, &count);
	for (i = 0; i < count; i++) {
		if (file->seeked_keywords[i] != '0')
			array_append(keywords, &map[i], 1);
	}

	return 0;
}

static int dbox_sync_full_mail(struct dbox_sync_context *ctx, uint32_t *seq_r)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	const struct dbox_mail_header *hdr = &mbox->file->seeked_mail_header;
	enum mail_flags flags;
        struct mail_keywords *keywords;
	ARRAY_TYPE(keyword_indexes) keywords_arr;
	uint32_t seq;
	uint64_t hdr_offset = mbox->file->seeked_offset;

	/* FIXME: mails can be in two places at the same time if we crashed
	   during copying expunge */

	i_assert(hdr->expunged != '1');

	if (mbox->file->seeked_uid >= ctx->mail_index_next_uid) {
		/* new mail. append it. */
		mail_index_append(ctx->trans, mbox->file->seeked_uid, &seq);
		*seq_r = 0;
	} else {
		if (mail_index_lookup_uid_range(ctx->sync_view,
						mbox->file->seeked_uid,
						mbox->file->seeked_uid,
						&seq, &seq) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			return -1;
		}
		if (seq == 0) {
			/* not found. it should have been there. */
			mail_storage_set_critical(&mbox->storage->storage,
				"dbox %s sync: "
				"UID %u inserted in the middle of mailbox",
				mbox->path, mbox->file->seeked_uid);
			mail_index_mark_corrupted(mbox->ibox.index);
			return -1;
		}
		*seq_r = seq;
	}

	flags = 0;
	if (hdr->answered == '1')
		flags |= MAIL_ANSWERED;
	if (hdr->flagged == '1')
		flags |= MAIL_FLAGGED;
	if (hdr->deleted == '1')
		flags |= MAIL_DELETED;
	if (hdr->seen == '1')
		flags |= MAIL_SEEN;
	if (hdr->draft == '1')
		flags |= MAIL_DRAFT;
	mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE, flags);

	t_push();
	t_array_init(&keywords_arr, mbox->file->keyword_count);
	if (dbox_mail_get_keywords(mbox, mbox->file, &keywords_arr) < 0) {
		t_pop();
		return -1;
	}
	keywords = mail_index_keywords_create_from_indexes(ctx->trans,
							   &keywords_arr);
	mail_index_update_keywords(ctx->trans, seq, MODIFY_REPLACE, keywords);
	mail_index_keywords_free(&keywords);
	t_pop();

	mail_index_update_ext(ctx->trans, seq, mbox->dbox_file_ext_idx,
			      &mbox->file->file_seq, NULL);
	mail_index_update_ext(ctx->trans, seq, mbox->dbox_offset_ext_idx,
			      &hdr_offset, NULL);
	return 0;
}

static int dbox_sync_full_file(struct dbox_sync_context *ctx, uint32_t file_seq)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	struct dbox_uidlist_entry entry;
	uint32_t seq;
	int ret;

	if ((ret = dbox_file_seek(mbox, file_seq, 0, FALSE)) < 0) {
		/* error / broken file */
		return -1;
	}
	if (ret == 0) {
		/* broken file, but without any useful data in it */
		if (unlink(mbox->file->path) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"unlink(%s) failed: %m", mbox->file->path);
			return -1;
		}
		return 0;
	}

	memset(&entry, 0, sizeof(entry));
	entry.file_seq = file_seq;
	t_array_init(&entry.uid_list, 64);

	if (mbox->file->seeked_mail_header.expunged != '0') {
		/* first mail expunged */
		ret = dbox_file_seek_next_nonexpunged(mbox);
	}
	while (ret > 0) {
		if (dbox_sync_full_mail(ctx, &seq) < 0)
			return -1;

		/* add to this file's uid list */
		seq_range_array_add(&entry.uid_list, 0,
				    ctx->mbox->file->seeked_uid);
		if (seq != 0) {
			/* add to the whole mailbox's exist list so we can
			   expunge the mails that weren't found. seq=0 is
			   given for newly appended mails */
			seq_range_array_add(&ctx->exists, 0, seq);
		}

		ret = dbox_file_seek_next_nonexpunged(mbox);
	}
	if (ret == 0 && array_count(&entry.uid_list) == 0) {
		/* all mails expunged in the file */
		if (unlink(mbox->file->path) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"unlink(%s) failed: %m", mbox->file->path);
			return -1;
		}
	} else {
		dbox_uidlist_sync_append(ctx->uidlist_sync_ctx, &entry);
	}
	return ret;
}

static void dbox_sync_full_expunge_nonfound(struct dbox_sync_context *ctx)
{
	const struct seq_range *exists;
	const struct mail_index_header *hdr;
	unsigned int i, count;
	uint32_t seq = 1;

	exists = array_get(&ctx->exists, &count);
	for (i = 0; i < count; i++) {
		/* expunge seq .. exists[i]-1 */
		while (seq < exists[i].seq1) {
			mail_index_expunge(ctx->trans, seq);
			seq++;
		}
		seq = exists[i].seq2 + 1;
	}

	hdr = mail_index_get_header(ctx->sync_view);
	while (seq <= hdr->messages_count) {
		mail_index_expunge(ctx->trans, seq);
		seq++;
	}
}

int dbox_sync_full(struct dbox_sync_context *ctx)
{
	struct dbox_mailbox *mbox = ctx->mbox;
	const struct mail_index_header *hdr;
	unsigned int file_prefix_len = strlen(DBOX_MAIL_FILE_PREFIX);
	uint32_t file_seq;
	DIR *dirp;
	struct dirent *dp;
	int ret = 0;

	/* go through msg.* files, sync them to index and based on it
	   write dbox's index file */
	dirp = opendir(mbox->path);
	if (dirp == NULL) {
		mail_storage_set_critical(&mbox->storage->storage,
					  "opendir(%s) failed: %m", mbox->path);
		return -1;
	}

	hdr = mail_index_get_header(ctx->sync_view);
	ctx->mail_index_next_uid = hdr->next_uid;

	dbox_uidlist_sync_from_scratch(ctx->uidlist_sync_ctx);
	i_array_init(&ctx->exists, 128);

	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp(dp->d_name, DBOX_MAIL_FILE_PREFIX,
			    file_prefix_len) != 0 ||
		    !is_numeric(dp->d_name + file_prefix_len, '\0'))
			continue;

		file_seq = (uint32_t)strtoul(dp->d_name + file_prefix_len,
					     NULL, 10);
		t_push();
		ret = dbox_sync_full_file(ctx, file_seq);
		t_pop();
		if (ret < 0)
			break;
	}
	if (closedir(dirp) < 0) {
		mail_storage_set_critical(&mbox->storage->storage,
			"closedir(%s) failed: %m", mbox->path);
		ret = -1;
	}

	if (ret == 0)
		dbox_sync_full_expunge_nonfound(ctx);

	array_free(&ctx->exists);
	return ret;
}
