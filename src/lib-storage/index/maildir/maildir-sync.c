/*
   1. read files in maildir
   2. see if they're all found in uidlist read in memory
   3. if not, check if uidlist's mtime has changed and read it if so
   4. if still not, lock uidlist, sync it once more and generate UIDs for new
      files
   5. apply changes in transaction log
   6. apply changes in maildir to index
*/

/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILDIR_SYNC_SECS 1

#define MAILDIR_FILENAME_FLAG_FOUND 128

struct maildir_sync_context {
        struct index_mailbox *ibox;
	const char *new_dir, *cur_dir;

        struct maildir_uidlist_sync_ctx *uidlist_sync_ctx;
};

static int maildir_expunge(struct index_mailbox *ibox, const char *path,
			   void *context __attr_unused__)
{
	if (unlink(path) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(ibox->box.storage,
				  "unlink(%s) failed: %m", path);
	return -1;
}

static int maildir_sync_flags(struct index_mailbox *ibox, const char *path,
			      void *context)
{
	struct mail_index_sync_rec *syncrec = context;
	const char *newpath;
	enum mail_flags flags;
	uint8_t flags8;
        custom_flags_mask_t custom_flags;

	(void)maildir_filename_get_flags(path, &flags, custom_flags);

	flags8 = flags;
	mail_index_sync_flags_apply(syncrec, &flags8, custom_flags);

	newpath = maildir_filename_set_flags(path, flags8, custom_flags);
	if (rename(path, newpath) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(ibox->box.storage,
				  "rename(%s, %s) failed: %m", path, newpath);
	return -1;
}

static int maildir_sync_record(struct index_mailbox *ibox,
			       struct mail_index_view *view,
			       struct mail_index_sync_rec *syncrec)
{
	uint32_t seq, uid;

	switch (syncrec->type) {
	case MAIL_INDEX_SYNC_TYPE_APPEND:
		break;
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
		for (seq = syncrec->seq1; seq <= syncrec->seq2; seq++) {
			if (mail_index_lookup_uid(view, seq, &uid) < 0)
				return -1;
			if (maildir_file_do(ibox, uid, maildir_expunge,
					    NULL) < 0)
				return -1;
		}
		break;
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
		for (seq = syncrec->seq1; seq <= syncrec->seq2; seq++) {
			if (mail_index_lookup_uid(view, seq, &uid) < 0)
				return -1;
			if (maildir_file_do(ibox, uid, maildir_sync_flags,
					    syncrec) < 0)
				return -1;
		}
		break;
	}

	return 0;
}

int maildir_sync_last_commit(struct index_mailbox *ibox)
{
        struct mail_index_view *view;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_sync_rec sync_rec;
	int ret;

	if (ibox->commit_log_file_seq == 0)
		return 0;

	ret = mail_index_sync_begin(ibox->index, &sync_ctx, &view,
				    ibox->commit_log_file_seq,
				    ibox->commit_log_file_offset);
	if (ret > 0) {
		while ((ret = mail_index_sync_next(sync_ctx, &sync_rec)) > 0) {
			if (maildir_sync_record(ibox, view, &sync_rec) < 0) {
				ret = -1;
				break;
			}
		}
		if (mail_index_sync_end(sync_ctx) < 0)
			ret = -1;
	}

	if (ret == 0) {
		ibox->commit_log_file_seq = 0;
		ibox->commit_log_file_offset = 0;
	} else {
		mail_storage_set_index_error(ibox);
	}
	return ret;
}

static struct maildir_sync_context *
maildir_sync_context_new(struct index_mailbox *ibox)
{
        struct maildir_sync_context *ctx;

	ctx = t_new(struct maildir_sync_context, 1);
	ctx->ibox = ibox;
	ctx->new_dir = t_strconcat(ibox->path, "/new", NULL);
	ctx->cur_dir = t_strconcat(ibox->path, "/cur", NULL);
	return ctx;
}

static void maildir_sync_deinit(struct maildir_sync_context *ctx)
{
	if (ctx->uidlist_sync_ctx != NULL)
		(void)maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
}

static int maildir_fix_duplicate(struct index_mailbox *ibox, const char *dir,
				 const char *old_fname)
{
	const char *new_fname, *old_path, *new_path;
	int ret = 0;

	t_push();

	old_path = t_strconcat(dir, "/", old_fname, NULL);
	new_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	new_path = t_strconcat(ibox->path, "/new/", new_fname, NULL);

	if (rename(old_path, new_path) == 0) {
		i_warning("Fixed duplicate in %s: %s -> %s",
			  ibox->path, old_fname, new_fname);
	} else if (errno != ENOENT) {
		mail_storage_set_critical(ibox->box.storage,
			"rename(%s, %s) failed: %m", old_path, new_path);
		ret = -1;
	}
	t_pop();

	return ret;
}

static int maildir_scan_dir(struct maildir_sync_context *ctx, int new_dir)
{
	struct mail_storage *storage = ctx->ibox->box.storage;
	const char *dir;
	DIR *dirp;
	string_t *src, *dest;
	struct dirent *dp;
	int move_new, this_new, ret = 1;

	src = t_str_new(1024);
	dest = t_str_new(1024);

	dir = new_dir ? ctx->new_dir : ctx->cur_dir;
	dirp = opendir(dir);
	if (dirp == NULL) {
		mail_storage_set_critical(storage,
					  "opendir(%s) failed: %m", dir);
		return -1;
	}

	move_new = new_dir;
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		this_new = new_dir;
		if (move_new) {
			str_truncate(src, 0);
			str_truncate(dest, 0);
			str_printfa(src, "%s/%s", ctx->new_dir, dp->d_name);
			str_printfa(dest, "%s/%s", ctx->cur_dir, dp->d_name);
			if (rename(str_c(src), str_c(dest)) == 0 ||
			    ENOTFOUND(errno)) {
				/* moved - we'll look at it later in cur/ dir */
				this_new = FALSE;
				continue;
			} else if (ENOSPACE(errno)) {
				/* not enough disk space, leave here */
				move_new = FALSE;
			} else {
				mail_storage_set_critical(storage,
					"rename(%s, %s) failed: %m",
					str_c(src), str_c(dest));
			}
		}

		ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
						dp->d_name, this_new);
		if (ret <= 0) {
			if (ret < 0)
				break;

			/* possibly duplicate - try fixing it */
			if (maildir_fix_duplicate(ctx->ibox,
						  dir, dp->d_name) < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(storage,
					  "closedir(%s) failed: %m", dir);
	}
	return ret < 0 ? -1 : 0;
}

static int maildir_sync_quick_check(struct maildir_sync_context *ctx,
				    int *new_changed_r, int *cur_changed_r)
{
	struct index_mailbox *ibox = ctx->ibox;
	struct stat st;
	time_t new_mtime, cur_mtime;

	*new_changed_r = *cur_changed_r = FALSE;

	if (stat(ctx->new_dir, &st) < 0) {
		mail_storage_set_critical(ibox->box.storage,
					  "stat(%s) failed: %m", ctx->new_dir);
		return -1;
	}
	new_mtime = st.st_mtime;

	if (stat(ctx->cur_dir, &st) < 0) {
		mail_storage_set_critical(ibox->box.storage,
					  "stat(%s) failed: %m", ctx->cur_dir);
		return -1;
	}
	cur_mtime = st.st_mtime;

	if (new_mtime != ibox->last_new_mtime ||
	    new_mtime >= ibox->last_sync - MAILDIR_SYNC_SECS) {
		*new_changed_r = TRUE;
		ibox->last_new_mtime = new_mtime;
	}
	if (cur_mtime != ibox->last_cur_mtime ||
	    (cur_mtime >= ibox->last_sync - MAILDIR_SYNC_SECS &&
	     ioloop_time - ibox->last_sync > MAILDIR_SYNC_SECS)) {
		/* cur/ changed, or delayed cur/ check */
		*cur_changed_r = TRUE;
		ibox->last_cur_mtime = cur_mtime;
	}
	ibox->last_sync = ioloop_time;

	return 0;
}

static int maildir_sync_index(struct maildir_sync_context *ctx)
{
	struct index_mailbox *ibox = ctx->ibox;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_sync_rec sync_rec;
	struct maildir_uidlist_iter_ctx *iter;
	struct mail_index_transaction *trans;
	struct mail_index_view *view;
	const struct mail_index_header *hdr;
	const struct mail_index_record *rec;
	uint32_t seq, uid, uflags;
	const char *filename;
	enum mail_flags flags;
	custom_flags_mask_t custom_flags;
	int ret;

	if (mail_index_sync_begin(ibox->index, &sync_ctx, &view,
				  (uint32_t)-1, (uoff_t)-1) <= 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}

	ret = mail_index_get_header(view, &hdr);
	i_assert(ret == 0); /* view is locked, can't happen */

	trans = mail_index_transaction_begin(view, FALSE);

	seq = 0;
	iter = maildir_uidlist_iter_init(ibox->uidlist);
	while (maildir_uidlist_iter_next(iter, &uid, &uflags, &filename)) {
		maildir_filename_get_flags(filename, &flags, custom_flags);

	__again:
		seq++;
		if (seq > hdr->messages_count) {
			mail_index_append(trans, uid, &seq);
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						flags, custom_flags);
			continue;
		}

		if (mail_index_lookup(view, seq, &rec) < 0) {
			mail_storage_set_index_error(ibox);
			ret = -1;
			break;
		}

		if (rec->uid < uid) {
			/* expunged */
			mail_index_expunge(trans, seq);
			goto __again;
		}

		if (rec->uid > uid) {
			/* new UID in the middle of the mailbox -
			   shouldn't happen */
			mail_storage_set_critical(ibox->box.storage,
				"Maildir sync: UID inserted in the middle "
				"of mailbox (%u > %u)", rec->uid, uid);
			mail_index_mark_corrupted(ibox->index);
			ret = -1;
			break;
		}

		maildir_filename_get_flags(filename, &flags, custom_flags);
		if (rec->flags & MAIL_RECENT)
			flags |= MAIL_RECENT;
		if ((uint8_t)flags != (rec->flags & MAIL_FLAGS_MASK) ||
		    memcmp(custom_flags, rec->custom_flags,
			   INDEX_CUSTOM_FLAGS_BYTE_COUNT) != 0) {
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						flags, custom_flags);
		}
	}
	maildir_uidlist_iter_deinit(iter);

	if (ret < 0)
		mail_index_transaction_rollback(trans);
	else {
		uint32_t seq;
		uoff_t offset;

		if (mail_index_transaction_commit(trans, &seq, &offset) < 0)
			mail_storage_set_index_error(ibox);
		else {
			ibox->commit_log_file_seq = seq;
			ibox->commit_log_file_offset = offset;
		}
	}

	/* now, sync the index */
	while ((ret = mail_index_sync_next(sync_ctx, &sync_rec)) > 0) {
		if (maildir_sync_record(ibox, view, &sync_rec) < 0) {
			ret = -1;
			break;
		}
	}
	if (mail_index_sync_end(sync_ctx) < 0)
		ret = -1;

	if (ret == 0) {
		ibox->commit_log_file_seq = 0;
		ibox->commit_log_file_offset = 0;
	} else {
		mail_storage_set_index_error(ibox);
	}

	return ret;
}

static int maildir_sync_context(struct maildir_sync_context *ctx,
				int *changes_r)
{
	int ret, new_changed, cur_changed;

	if (maildir_sync_quick_check(ctx, &new_changed, &cur_changed) < 0)
		return -1;

	ctx->uidlist_sync_ctx = maildir_uidlist_sync_init(ctx->ibox->uidlist);

	if (maildir_scan_dir(ctx, TRUE) < 0)
		return -1;
	if (maildir_scan_dir(ctx, FALSE) < 0)
		return -1;

	ret = maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
        ctx->uidlist_sync_ctx = NULL;

	if (ret == 0)
		ret = maildir_sync_index(ctx);
	return ret;
}

static int maildir_sync_context_readonly(struct maildir_sync_context *ctx)
{
	int ret;

	ctx->uidlist_sync_ctx = maildir_uidlist_sync_init(ctx->ibox->uidlist);

	if (maildir_scan_dir(ctx, TRUE) < 0)
		return -1;
	if (maildir_scan_dir(ctx, FALSE) < 0)
		return -1;

	ret = maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
        ctx->uidlist_sync_ctx = NULL;

	return ret;
}

int maildir_storage_sync_readonly(struct index_mailbox *ibox)
{
        struct maildir_sync_context *ctx;
	int ret;

	ctx = maildir_sync_context_new(ibox);
	ret = maildir_sync_context_readonly(ctx);
	maildir_sync_deinit(ctx);
	return ret;
}

int maildir_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct maildir_sync_context *ctx;
	int changes, ret;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <= ioloop_time) {
		ibox->sync_last_check = ioloop_time;

		ctx = maildir_sync_context_new(ibox);
		ret = maildir_sync_context(ctx, &changes);
		maildir_sync_deinit(ctx);

		if (ret < 0)
			return -1;
	}

	return index_storage_sync(box, flags);
}
