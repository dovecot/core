/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "fdatasync-path.h"
#include "eacces-error.h"
#include "str.h"
#include "index-mail.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "maildir-filename.h"
#include "maildir-sync.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

#define MAILDIR_FILENAME_FLAG_MOVED 0x10000000

struct maildir_filename {
	struct maildir_filename *next;
	const char *tmp_name, *dest_basename;
	const char *pop3_uidl, *guid;

	uoff_t size, vsize;
	enum mail_flags flags;
	unsigned int preserve_filename:1;
	unsigned int keywords_count;
	/* unsigned int keywords[]; */
};

struct maildir_save_context {
	struct mail_save_context ctx;
	pool_t pool;

	struct maildir_mailbox *mbox;
	struct mail_index_transaction *trans;
	struct maildir_uidlist_sync_ctx *uidlist_sync_ctx;
	struct maildir_keywords_sync_ctx *keywords_sync_ctx;
	struct maildir_index_sync_context *sync_ctx;
	struct mail *mail, *cur_dest_mail;

	const char *tmpdir, *newdir, *curdir;
	struct maildir_filename *files, **files_tail, *file_last;
	unsigned int files_count;

	buffer_t keywords_buffer;
	ARRAY_TYPE(keyword_indexes) keywords_array;

	struct istream *input;
	int fd;
	uint32_t first_seq, seq, last_nonrecent_uid;

	unsigned int have_keywords:1;
	unsigned int have_preserved_filenames:1;
	unsigned int locked:1;
	unsigned int failed:1;
	unsigned int last_save_finished:1;
	unsigned int locked_uidlist_refresh:1;
};

static int maildir_file_move(struct maildir_save_context *ctx,
			     struct maildir_filename *mf, const char *destname,
			     bool newdir)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	const char *tmp_path, *new_path;

	i_assert(*destname != '\0');
	i_assert(*mf->tmp_name != '\0');

	/* if we have flags, we'll move it to cur/ directly, because files in
	   new/ directory can't have flags. alternative would be to write it
	   in new/ and set the flags dirty in index file, but in that case
	   external MUAs would see wrong flags. */
	tmp_path = t_strconcat(ctx->tmpdir, "/", mf->tmp_name, NULL);
	new_path = newdir ?
		t_strconcat(ctx->newdir, "/", destname, NULL) :
		t_strconcat(ctx->curdir, "/", destname, NULL);

	/* maildir spec says we should use link() + unlink() here. however
	   since our filename is guaranteed to be unique, rename() works just
	   as well, except faster. even if the filename wasn't unique, the
	   problem could still happen if the file was already moved from
	   new/ to cur/, so link() doesn't really provide any safety anyway.

	   Besides the small temporary performance benefits, this rename() is
	   almost required with OSX's HFS+ filesystem, since it implements
	   hard links in a pretty ugly way, which makes the performance crawl
	   when a lot of hard links are used. */
	if (rename(tmp_path, new_path) == 0) {
		mf->flags |= MAILDIR_FILENAME_FLAG_MOVED;
		return 0;
	} else if (ENOSPACE(errno)) {
		mail_storage_set_error(storage, MAIL_ERROR_NOSPACE,
				       MAIL_ERRSTR_NO_SPACE);
		return -1;
	} else {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  tmp_path, new_path);
		return -1;
	}
}

static struct mail_save_context *
maildir_save_transaction_init(struct mailbox_transaction_context *t)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->box;
	struct maildir_save_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("maildir_save_context", 4096);
	ctx = p_new(pool, struct maildir_save_context, 1);
	ctx->ctx.transaction = t;
	ctx->pool = pool;
	ctx->mbox = mbox;
	ctx->trans = t->itrans;
	ctx->files_tail = &ctx->files;
	ctx->fd = -1;

	ctx->tmpdir = p_strconcat(pool, mbox->box.path, "/tmp", NULL);
	ctx->newdir = p_strconcat(pool, mbox->box.path, "/new", NULL);
	ctx->curdir = p_strconcat(pool, mbox->box.path, "/cur", NULL);

	buffer_create_const_data(&ctx->keywords_buffer, NULL, 0);
	array_create_from_buffer(&ctx->keywords_array, &ctx->keywords_buffer,
				 sizeof(unsigned int));
	ctx->last_save_finished = TRUE;
	return &ctx->ctx;
}

struct maildir_filename *
maildir_save_add(struct mail_save_context *_ctx, const char *tmp_fname,
		 struct mail *src_mail)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct maildir_filename *mf;
	struct istream *input;
	unsigned int keyword_count;

	i_assert(*tmp_fname != '\0');

	/* allow caller to specify recent flag only when uid is specified
	   (we're replicating, converting, etc.). */
	if (_ctx->uid == 0)
		_ctx->flags |= MAIL_RECENT;
	else if ((_ctx->flags & MAIL_RECENT) == 0 &&
		 ctx->last_nonrecent_uid < _ctx->uid)
		ctx->last_nonrecent_uid = _ctx->uid;

	/* now, we want to be able to rollback the whole append session,
	   so we'll just store the name of this temp file and move it later
	   into new/ or cur/. */
	/* @UNSAFE */
	keyword_count = _ctx->keywords == NULL ? 0 : _ctx->keywords->count;
	mf = p_malloc(ctx->pool, sizeof(*mf) +
		      sizeof(unsigned int) * keyword_count);
	mf->tmp_name = mf->dest_basename = p_strdup(ctx->pool, tmp_fname);
	mf->flags = _ctx->flags;
	mf->size = (uoff_t)-1;
	mf->vsize = (uoff_t)-1;

	ctx->file_last = mf;
	i_assert(*ctx->files_tail == NULL);
	*ctx->files_tail = mf;
	ctx->files_tail = &mf->next;
	ctx->files_count++;

	if (_ctx->keywords != NULL) {
		/* @UNSAFE */
		mf->keywords_count = keyword_count;
		memcpy(mf + 1, _ctx->keywords->idx,
		       sizeof(unsigned int) * keyword_count);
		ctx->have_keywords = TRUE;
	}
	if (_ctx->pop3_uidl != NULL)
		mf->pop3_uidl = p_strdup(ctx->pool, _ctx->pop3_uidl);

	/* insert into index */
	mail_index_append(ctx->trans, _ctx->uid, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq,
				MODIFY_REPLACE, _ctx->flags & ~MAIL_RECENT);
	if (_ctx->keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, _ctx->keywords);
	}
	if (_ctx->min_modseq != 0) {
		mail_index_update_modseq(ctx->trans, ctx->seq,
					 _ctx->min_modseq);
	}

	if (ctx->first_seq == 0) {
		ctx->first_seq = ctx->seq;
		i_assert(ctx->files->next == NULL);
	}

	if (_ctx->dest_mail == NULL) {
		if (ctx->mail == NULL)
			ctx->mail = mail_alloc(_ctx->transaction, 0, NULL);
		_ctx->dest_mail = ctx->mail;
	}
	mail_set_seq(_ctx->dest_mail, ctx->seq);
	_ctx->dest_mail->saving = TRUE;

	if (ctx->input == NULL) {
		/* copying with hardlinking. */
		i_assert(src_mail != NULL);
		index_copy_cache_fields(_ctx, src_mail, ctx->seq);
		ctx->cur_dest_mail = NULL;
	} else {
		input = index_mail_cache_parse_init(_ctx->dest_mail,
						    ctx->input);
		i_stream_unref(&ctx->input);
		ctx->input = input;
		ctx->cur_dest_mail = _ctx->dest_mail;
	}
	return mf;
}

void maildir_save_set_dest_basename(struct mail_save_context *_ctx,
				    struct maildir_filename *mf,
				    const char *basename)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	mf->preserve_filename = TRUE;
	mf->dest_basename = p_strdup(ctx->pool, basename);
	ctx->have_preserved_filenames = TRUE;
}

void maildir_save_set_sizes(struct maildir_filename *mf,
			    uoff_t size, uoff_t vsize)
{
	mf->size = size;
	mf->vsize = vsize;
}

static bool
maildir_get_dest_filename(struct maildir_save_context *ctx,
			  struct maildir_filename *mf,
			  const char **fname_r)
{
	const char *basename = mf->dest_basename;

	if (mf->size != (uoff_t)-1 && !mf->preserve_filename) {
		basename = t_strdup_printf("%s,%c=%"PRIuUOFF_T, basename,
					   MAILDIR_EXTRA_FILE_SIZE, mf->size);
	}

	if (mf->vsize != (uoff_t)-1 && !mf->preserve_filename) {
		basename = t_strdup_printf("%s,%c=%"PRIuUOFF_T, basename,
					   MAILDIR_EXTRA_VIRTUAL_SIZE,
					   mf->vsize);
	}

	if (mf->keywords_count == 0) {
		if ((mf->flags & MAIL_FLAGS_MASK) == MAIL_RECENT) {
			*fname_r = basename;
			return TRUE;
		}

		*fname_r = maildir_filename_set_flags(NULL, basename,
					mf->flags & MAIL_FLAGS_MASK, NULL);
		return FALSE;
	}

	i_assert(ctx->keywords_sync_ctx != NULL || mf->keywords_count == 0);
	buffer_create_const_data(&ctx->keywords_buffer, mf + 1,
				 mf->keywords_count * sizeof(unsigned int));
	*fname_r = maildir_filename_set_flags(ctx->keywords_sync_ctx, basename,
					      mf->flags & MAIL_FLAGS_MASK,
					      &ctx->keywords_array);
	return FALSE;
}

static const char *maildir_mf_get_path(struct maildir_save_context *ctx,
				       struct maildir_filename *mf)
{
	const char *fname, *dir;

	if ((mf->flags & MAILDIR_FILENAME_FLAG_MOVED) == 0) {
		/* file is still in tmp/ */
		return t_strdup_printf("%s/%s", ctx->tmpdir, mf->tmp_name);
	}

	/* already moved to new/ or cur/ */
	dir = maildir_get_dest_filename(ctx, mf, &fname) ?
		ctx->newdir : ctx->curdir;
	return t_strdup_printf("%s/%s", dir, fname);
}

const char *maildir_save_file_get_path(struct mailbox_transaction_context *t,
				       uint32_t seq)
{
	struct maildir_save_context *save_ctx =
		(struct maildir_save_context *)t->save_ctx;
	struct maildir_filename *mf;

	i_assert(seq >= save_ctx->first_seq);

	seq -= save_ctx->first_seq;
	mf = save_ctx->files;
	while (seq > 0) {
		mf = mf->next;
		i_assert(mf != NULL);
		seq--;
	}

	return maildir_mf_get_path(save_ctx, mf);
}

static int maildir_create_tmp(struct maildir_mailbox *mbox, const char *dir,
			      const char **fname_r)
{
	struct mailbox *box = &mbox->box;
	unsigned int prefix_len;
	const char *tmp_fname;
	string_t *path;
	mode_t old_mask;
	int fd;

	path = t_str_new(256);
	str_append(path, dir);
	str_append_c(path, '/');
	prefix_len = str_len(path);

	do {
		tmp_fname = maildir_filename_generate();
		str_truncate(path, prefix_len);
		str_append(path, tmp_fname);

		/* the generated filename is unique. the only reason why it
		   might return an existing filename is if the time moved
		   backwards. so we'll use O_EXCL anyway, although it's mostly
		   useless. */
		old_mask = umask(0777 & ~box->file_create_mode);
		fd = open(str_c(path),
			  O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0777);
		umask(old_mask);
	} while (fd == -1 && errno == EEXIST);

	*fname_r = tmp_fname;
	if (fd == -1) {
		if (ENOSPACE(errno)) {
			mail_storage_set_error(box->storage,
				MAIL_ERROR_NOSPACE, MAIL_ERRSTR_NO_SPACE);
		} else {
			mail_storage_set_critical(box->storage,
				"open(%s) failed: %m", str_c(path));
		}
	} else if (box->file_create_gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, box->file_create_gid) < 0) {
			if (errno == EPERM) {
				mail_storage_set_critical(box->storage, "%s",
					eperm_error_get_chgrp("fchown",
						str_c(path),
						box->file_create_gid,
						box->file_create_gid_origin));
			} else {
				mail_storage_set_critical(box->storage,
					"fchown(%s) failed: %m", str_c(path));
			}
		}
	}

	return fd;
}

struct mail_save_context *
maildir_save_alloc(struct mailbox_transaction_context *t)
{
	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL)
		t->save_ctx = maildir_save_transaction_init(t);
	return t->save_ctx;
}

int maildir_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct maildir_filename *mf;

	/* new mail, new failure state */
	ctx->failed = FALSE;

	T_BEGIN {
		/* create a new file in tmp/ directory */
		const char *fname;

		ctx->fd = maildir_create_tmp(ctx->mbox, ctx->tmpdir, &fname);
		if (ctx->fd == -1)
			ctx->failed = TRUE;
		else {
			if (ctx->mbox->storage->storage.set->mail_save_crlf)
				ctx->input = i_stream_create_crlf(input);
			else
				ctx->input = i_stream_create_lf(input);
			mf = maildir_save_add(_ctx, fname, NULL);
			if (_ctx->guid != NULL) {
				maildir_save_set_dest_basename(_ctx, mf,
							       _ctx->guid);
			}
		}
	} T_END;

	if (!ctx->failed) {
		_ctx->output = o_stream_create_fd_file(ctx->fd, 0, FALSE);
		o_stream_cork(_ctx->output);
		ctx->last_save_finished = FALSE;
	}
	return ctx->failed ? -1 : 0;
}

int maildir_save_continue(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;

	if (ctx->failed)
		return -1;

	do {
		if (o_stream_send_istream(_ctx->output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_send_istream(%s/%s) "
					"failed: %m",
					ctx->tmpdir, ctx->file_last->tmp_name);
			}
			ctx->failed = TRUE;
			return -1;
		}
		if (ctx->cur_dest_mail != NULL)
			index_mail_cache_parse_continue(ctx->cur_dest_mail);

		/* both tee input readers may consume data from our primary
		   input stream. we'll have to make sure we don't return with
		   one of the streams still having data in them. */
	} while (i_stream_read(ctx->input) > 0);
	return 0;
}

static int maildir_save_finish_received_date(struct maildir_save_context *ctx,
					     const char *path)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	struct utimbuf buf;
	struct stat st;

	if (ctx->ctx.received_date != (time_t)-1) {
		/* set the received_date by modifying mtime */
		buf.actime = ioloop_time;
		buf.modtime = ctx->ctx.received_date;

		if (utime(path, &buf) < 0) {
			mail_storage_set_critical(storage,
						  "utime(%s) failed: %m", path);
			return -1;
		}
	} else if (ctx->fd != -1) {
		if (fstat(ctx->fd, &st) == 0)
			ctx->ctx.received_date = st.st_mtime;
		else {
			mail_storage_set_critical(storage,
						  "fstat(%s) failed: %m", path);
			return -1;
		}
	} else {
		/* hardlinked */
		if (stat(path, &st) == 0)
			ctx->ctx.received_date = st.st_mtime;
		else {
			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static void maildir_save_remove_last_filename(struct maildir_save_context *ctx)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)ctx->ctx.transaction;
	struct maildir_filename **fm;

	mail_index_expunge(ctx->trans, ctx->seq);
	/* currently we can't just drop pending cache updates for this one
	   specific record, so we'll reset the whole cache transaction. */
	mail_cache_transaction_reset(t->cache_trans);
	ctx->seq--;

	for (fm = &ctx->files; (*fm)->next != NULL; fm = &(*fm)->next) ;
	i_assert(*fm == ctx->file_last);
	*fm = NULL;

	ctx->files_tail = fm;
	ctx->file_last = NULL;
	ctx->files_count--;
}

static int maildir_save_finish_real(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	const char *path;
	int output_errno;

	ctx->last_save_finished = TRUE;
	if (ctx->failed && ctx->fd == -1) {
		/* tmp file creation failed */
		return -1;
	}

	path = t_strconcat(ctx->tmpdir, "/", ctx->file_last->tmp_name, NULL);
	if (o_stream_flush(_ctx->output) < 0) {
		if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
				"o_stream_flush(%s) failed: %m", path);
		}
		ctx->failed = TRUE;
	}

	if (_ctx->save_date != (time_t)-1) {
		/* we can't change ctime, but we can add the date to cache */
		struct index_mail *mail = (struct index_mail *)_ctx->dest_mail;
		uint32_t t = _ctx->save_date;

		index_mail_cache_add(mail, MAIL_CACHE_SAVE_DATE, &t, sizeof(t));
	}

 	if (maildir_save_finish_received_date(ctx, path) < 0)
		ctx->failed = TRUE;

	if (ctx->cur_dest_mail != NULL) {
		index_mail_cache_parse_deinit(ctx->cur_dest_mail,
					      ctx->ctx.received_date,
					      !ctx->failed);
	}
	i_stream_unref(&ctx->input);

	/* remember the size in case we want to add it to filename */
	ctx->file_last->size = _ctx->output->offset;
	if (ctx->cur_dest_mail == NULL ||
	    mail_get_virtual_size(ctx->cur_dest_mail,
				  &ctx->file_last->vsize) < 0)
		ctx->file_last->vsize = (uoff_t)-1;

	output_errno = _ctx->output->stream_errno;
	o_stream_destroy(&_ctx->output);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER &&
	    !ctx->failed) {
		if (fsync(ctx->fd) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
						  "fsync(%s) failed: %m", path);
			}
			ctx->failed = TRUE;
		}
	}
	if (close(ctx->fd) < 0) {
		if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
						  "close(%s) failed: %m", path);
		}
		ctx->failed = TRUE;
	}
	ctx->fd = -1;

	if (ctx->failed) {
		/* delete the tmp file */
		if (unlink(path) < 0 && errno != ENOENT) {
			mail_storage_set_critical(storage,
				"unlink(%s) failed: %m", path);
		}

		errno = output_errno;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(storage,
				MAIL_ERROR_NOSPACE, MAIL_ERRSTR_NO_SPACE);
		} else if (errno != 0) {
			mail_storage_set_critical(storage,
				"write(%s) failed: %m", path);
		}

		maildir_save_remove_last_filename(ctx);
		return -1;
	}

	ctx->file_last = NULL;
	return 0;
}

int maildir_save_finish(struct mail_save_context *ctx)
{
	int ret;

	T_BEGIN {
		ret = maildir_save_finish_real(ctx);
	} T_END;
	index_save_context_free(ctx);
	return ret;
}

void maildir_save_cancel(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)maildir_save_finish(_ctx);
}

static void
maildir_save_unlink_files(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;

	for (mf = ctx->files; mf != NULL; mf = mf->next) T_BEGIN {
		(void)unlink(maildir_mf_get_path(ctx, mf));
	} T_END;
	ctx->files = NULL;
}

static int maildir_transaction_fsync_dirs(struct maildir_save_context *ctx,
					  bool new_changed, bool cur_changed)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;

	if (storage->set->parsed_fsync_mode == FSYNC_MODE_NEVER)
		return 0;

	if (new_changed) {
		if (fdatasync_path(ctx->newdir) < 0) {
			mail_storage_set_critical(storage,
				"fdatasync_path(%s) failed: %m", ctx->newdir);
			return -1;
		}
	}
	if (cur_changed) {
		if (fdatasync_path(ctx->curdir) < 0) {
			mail_storage_set_critical(storage,
				"fdatasync_path(%s) failed: %m", ctx->curdir);
			return -1;
		}
	}
	return 0;
}

static int seq_range_cmp(const struct seq_range *r1, const struct seq_range *r2)
{
	if (r1->seq1 < r2->seq2)
		return -1;
	else if (r1->seq1 > r2->seq2)
		return 1;
	else
		return 0;
}

static uint32_t
maildir_save_set_recent_flags(struct maildir_save_context *ctx)
{
	struct maildir_mailbox *mbox = ctx->mbox;
	ARRAY_TYPE(seq_range) saved_sorted_uids;
	const struct seq_range *uids;
	unsigned int i, count;
	uint32_t uid;

	count = array_count(&ctx->ctx.transaction->changes->saved_uids);
	if (count == 0)
		return 0;

	t_array_init(&saved_sorted_uids, count);
	array_append_array(&saved_sorted_uids,
			   &ctx->ctx.transaction->changes->saved_uids);
	array_sort(&saved_sorted_uids, seq_range_cmp);

	uids = array_get(&saved_sorted_uids, &count);
	for (i = 0; i < count; i++) {
		for (uid = uids[i].seq1; uid <= uids[i].seq2; uid++)
			index_mailbox_set_recent_uid(&mbox->box, uid);
	}
	return uids[count-1].seq2 + 1;
}

static int
maildir_save_sync_index(struct maildir_save_context *ctx)
{
	struct mailbox_transaction_context *_t = ctx->ctx.transaction;
	struct maildir_mailbox *mbox = ctx->mbox;
	uint32_t first_uid, next_uid, first_recent_uid;
	int ret;

	/* we'll need to keep the lock past the sync deinit */
	ret = maildir_uidlist_lock(mbox->uidlist);
	i_assert(ret > 0);

	if (maildir_sync_header_refresh(mbox) < 0)
		return -1;
	if ((ret = maildir_uidlist_refresh_fast_init(mbox->uidlist)) < 0)
		return -1;

	if (ret == 0) {
		/* uidlist doesn't exist. make sure all existing message
		   are added to uidlist first. */
		(void)maildir_storage_sync_force(mbox, 0);
	}

	if (maildir_sync_index_begin(mbox, NULL, &ctx->sync_ctx) < 0)
		return -1;
	ctx->keywords_sync_ctx =
		maildir_sync_get_keywords_sync_ctx(ctx->sync_ctx);

	/* now that uidlist is locked, make sure all the existing mails
	   have been added to index. we don't really look into the
	   maildir, just add all the new mails listed in
	   dovecot-uidlist to index. */
	if (maildir_sync_index(ctx->sync_ctx, TRUE) < 0)
		return -1;

	/* if messages were added to index, assign them UIDs */
	first_uid = maildir_uidlist_get_next_uid(mbox->uidlist);
	i_assert(first_uid != 0);
	mail_index_append_finish_uids(ctx->trans, first_uid,
				      &_t->changes->saved_uids);
	i_assert(ctx->files_count == seq_range_count(&_t->changes->saved_uids));

	/* these mails are all recent in our session */
	T_BEGIN {
		next_uid = maildir_save_set_recent_flags(ctx);
	} T_END;

	if ((mbox->box.flags & MAILBOX_FLAG_KEEP_RECENT) == 0)
		first_recent_uid = next_uid;
	else if (ctx->last_nonrecent_uid != 0)
		first_recent_uid = ctx->last_nonrecent_uid + 1;
	else
		first_recent_uid = 0;

	if (first_recent_uid != 0) {
		/* maildir_sync_index() dropped recent flags from
		   existing messages. we'll still need to drop recent
		   flags from these newly added messages. */
		mail_index_update_header(ctx->trans,
					 offsetof(struct mail_index_header,
						  first_recent_uid),
					 &first_recent_uid,
					 sizeof(first_recent_uid), FALSE);
	}
	return 0;
}

static void
maildir_save_rollback_index_changes(struct maildir_save_context *ctx)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)ctx->ctx.transaction;
	uint32_t seq;

	if (ctx->seq == 0)
		return;

	for (seq = ctx->seq; seq >= ctx->first_seq; seq--)
		mail_index_expunge(ctx->trans, seq);

	mail_cache_transaction_reset(t->cache_trans);
}

static bool maildir_filename_has_conflict(struct maildir_filename *mf,
					  struct maildir_filename *prev_mf)
{
	if (strcmp(mf->dest_basename, prev_mf->dest_basename) == 0) {
		/* already used this */
		return TRUE;
	}
	if (prev_mf->guid != NULL &&
	    strcmp(mf->dest_basename, prev_mf->guid) == 0) {
		/* previous filename also had a conflict */
		return TRUE;
	}
	return FALSE;
}

static void
maildir_filename_check_conflicts(struct maildir_save_context *ctx,
				 struct maildir_filename *mf,
				 struct maildir_filename *prev_mf)
{
	uoff_t size;

	if (!ctx->locked_uidlist_refresh) {
		(void)maildir_uidlist_refresh(ctx->mbox->uidlist);
		ctx->locked_uidlist_refresh = TRUE;
	}

	if ((prev_mf != NULL && maildir_filename_has_conflict(mf, prev_mf)) ||
	    maildir_uidlist_get_full_filename(ctx->mbox->uidlist,
					      mf->dest_basename) != NULL) {
		/* file already exists. give it another name.
		   but preserve the size/vsize in the filename if possible */
		if (maildir_filename_get_size(mf->dest_basename,
					      MAILDIR_EXTRA_FILE_SIZE, &size))
			mf->size = size;
		if (maildir_filename_get_size(mf->dest_basename,
					      MAILDIR_EXTRA_VIRTUAL_SIZE,
					      &size))
			mf->vsize = size;

		mf->guid = mf->dest_basename;
		mf->dest_basename = p_strdup(ctx->pool,
					     maildir_filename_generate());
		mf->preserve_filename = FALSE;
	}
}

static int
maildir_filename_dest_basename_cmp(struct maildir_filename *const *f1,
				   struct maildir_filename *const *f2)
{
	return strcmp((*f1)->dest_basename, (*f2)->dest_basename);
}

static int
maildir_save_move_files_to_newcur(struct maildir_save_context *ctx)
{
	ARRAY_DEFINE(files, struct maildir_filename *);
	struct maildir_filename *mf, *const *mfp, *prev_mf;
	bool newdir, new_changed, cur_changed;
	int ret;

	/* put files into an array sorted by the destination filename.
	   this way we can easily check if there are duplicate destination
	   filenames within this transaction. */
	t_array_init(&files, ctx->files_count);
	for (mf = ctx->files; mf != NULL; mf = mf->next)
		array_append(&files, &mf, 1);
	array_sort(&files, maildir_filename_dest_basename_cmp);

	new_changed = cur_changed = FALSE; prev_mf = FALSE;
	array_foreach(&files, mfp) {
		mf = *mfp;
		T_BEGIN {
			const char *dest;

			if (mf->preserve_filename) {
				maildir_filename_check_conflicts(ctx, mf,
								 prev_mf);
			}

			newdir = maildir_get_dest_filename(ctx, mf, &dest);
			if (newdir)
				new_changed = TRUE;
			else
				cur_changed = TRUE;
			ret = maildir_file_move(ctx, mf, dest, newdir);
		} T_END;
		if (ret < 0)
			return -1;
		prev_mf = mf;
	}

	if (ctx->locked) {
		i_assert(ctx->sync_ctx != NULL);
		maildir_sync_set_new_msgs_count(ctx->sync_ctx,
						array_count(&files));
	}
	return maildir_transaction_fsync_dirs(ctx, new_changed, cur_changed);
}

static void maildir_save_sync_uidlist(struct maildir_save_context *ctx)
{
	struct mailbox_transaction_context *t = ctx->ctx.transaction;
	struct maildir_filename *mf;
	struct seq_range_iter iter;
	enum maildir_uidlist_rec_flag flags;
	struct maildir_uidlist_rec *rec;
	unsigned int n = 0;
	uint32_t uid;
	bool newdir, bret;
	int ret;

	seq_range_array_iter_init(&iter, &t->changes->saved_uids);
	for (mf = ctx->files; mf != NULL; mf = mf->next) T_BEGIN {
		const char *dest;

		bret = seq_range_array_iter_nth(&iter, n++, &uid);
		i_assert(bret);

		newdir = maildir_get_dest_filename(ctx, mf, &dest);
		flags = MAILDIR_UIDLIST_REC_FLAG_RECENT;
		if (newdir)
			flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
		ret = maildir_uidlist_sync_next_uid(ctx->uidlist_sync_ctx,
						    dest, uid, flags, &rec);
		i_assert(ret > 0);
		i_assert(rec != NULL);
		if (mf->guid != NULL) {
			maildir_uidlist_sync_set_ext(ctx->uidlist_sync_ctx, rec,
				MAILDIR_UIDLIST_REC_EXT_GUID, mf->guid);
		}
		if (mf->pop3_uidl != NULL) {
			maildir_uidlist_sync_set_ext(ctx->uidlist_sync_ctx, rec,
				MAILDIR_UIDLIST_REC_EXT_POP3_UIDL,
				mf->pop3_uidl);
		}
	} T_END;
	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));
}

int maildir_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	enum maildir_uidlist_sync_flags sync_flags;
	int ret;

	i_assert(_ctx->output == NULL);
	i_assert(ctx->last_save_finished);

	if (ctx->files_count == 0) {
		/* the mail must be freed in the commit_pre() */
		if (ctx->mail != NULL)
			mail_free(&ctx->mail);
		return 0;
	}

	sync_flags = MAILDIR_UIDLIST_SYNC_PARTIAL |
		MAILDIR_UIDLIST_SYNC_NOREFRESH;

	if ((_t->flags & MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS) != 0) {
		/* we want to assign UIDs, we must lock uidlist */
	} else if (ctx->have_keywords) {
		/* keywords file updating relies on uidlist lock. */
	} else if (ctx->have_preserved_filenames) {
		/* we're trying to use some potentially existing filenames.
		   we must lock to avoid race conditions where two sessions
		   try to save the same filename. */
	} else {
		/* no requirement to lock uidlist. if we happen to get a lock,
		   assign uids. */
		sync_flags |= MAILDIR_UIDLIST_SYNC_TRYLOCK;
	}
	ret = maildir_uidlist_sync_init(ctx->mbox->uidlist, sync_flags,
					&ctx->uidlist_sync_ctx);
	if (ret > 0) {
		ctx->locked = TRUE;
		if (maildir_save_sync_index(ctx) < 0) {
			maildir_transaction_save_rollback(_ctx);
			return -1;
		}
	} else if (ret == 0 &&
		   (sync_flags & MAILDIR_UIDLIST_SYNC_TRYLOCK) != 0) {
		ctx->locked = FALSE;
		i_assert(ctx->uidlist_sync_ctx == NULL);
		/* since we couldn't lock uidlist, we'll have to drop the
		   appends to index. */
		maildir_save_rollback_index_changes(ctx);
	} else {
		maildir_transaction_save_rollback(_ctx);
		return -1;
	}

	T_BEGIN {
		ret = maildir_save_move_files_to_newcur(ctx);
	} T_END;
	if (ctx->locked) {
		if (ret == 0) {
			/* update dovecot-uidlist file. */
			maildir_save_sync_uidlist(ctx);
		}

		if (maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx,
						ret == 0) < 0)
			ret = -1;
	}

	_t->changes->uid_validity =
		maildir_uidlist_get_uid_validity(ctx->mbox->uidlist);

	if (ctx->mail != NULL) {
		/* Mail freeing may trigger cache updates and a call to
		   maildir_save_file_get_path(). Do this before finishing index
		   sync so we still have keywords_sync_ctx. */
		mail_free(&ctx->mail);
	}

	if (ctx->locked) {
		/* It doesn't matter if index syncing fails */
		ctx->keywords_sync_ctx = NULL;
		if (ret < 0)
			maildir_sync_index_rollback(&ctx->sync_ctx);
		else
			(void)maildir_sync_index_commit(&ctx->sync_ctx);
	}

	if (ret < 0) {
		ctx->keywords_sync_ctx = !ctx->have_keywords ? NULL :
			maildir_keywords_sync_init(ctx->mbox->keywords,
						   ctx->mbox->box.index);

		/* unlink the files we just moved in an attempt to rollback
		   the transaction. uidlist is still locked, so at least other
		   Dovecot instances haven't yet seen the files. we need
		   to have the keywords sync context to be able to generate
		   the destination filenames if keywords were used. */
		maildir_save_unlink_files(ctx);

		if (ctx->keywords_sync_ctx != NULL)
			maildir_keywords_sync_deinit(&ctx->keywords_sync_ctx);
		/* returning failure finishes the save_context */
		maildir_transaction_save_rollback(_ctx);
		return -1;
	}
	return 0;
}

void maildir_transaction_save_commit_post(struct mail_save_context *_ctx,
					  struct mail_index_transaction_commit_result *result ATTR_UNUSED)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	_ctx->transaction = NULL; /* transaction is already freed */

	if (ctx->locked)
		maildir_uidlist_unlock(ctx->mbox->uidlist);
	pool_unref(&ctx->pool);
}

void maildir_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	i_assert(_ctx->output == NULL);

	if (!ctx->last_save_finished)
		maildir_save_cancel(&ctx->ctx);

	/* delete files in tmp/ */
	maildir_save_unlink_files(ctx);

	if (ctx->uidlist_sync_ctx != NULL)
		(void)maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx, FALSE);
	if (ctx->sync_ctx != NULL)
		maildir_sync_index_rollback(&ctx->sync_ctx);
	if (ctx->locked)
		maildir_uidlist_unlock(ctx->mbox->uidlist);

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
	pool_unref(&ctx->pool);
}
