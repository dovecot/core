/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
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

struct maildir_filename {
	struct maildir_filename *next;
	const char *basename;

	uoff_t size, vsize;
	enum mail_flags flags;
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

	buffer_t *keywords_buffer;
	ARRAY_TYPE(keyword_indexes) keywords_array;

	struct istream *input;
	struct ostream *output;
	int fd;
	time_t received_date;
	uint32_t first_seq, seq;

	unsigned int want_mails:1;
	unsigned int have_keywords:1;
	unsigned int locked:1;
	unsigned int failed:1;
	unsigned int moving:1;
	unsigned int finished:1;
};

static int maildir_file_move(struct maildir_save_context *ctx,
			     const char *tmpname, const char *destname,
			     bool newdir)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	const char *tmp_path, *new_path;
	int ret;

	/* if we have flags, we'll move it to cur/ directly, because files in
	   new/ directory can't have flags. alternative would be to write it
	   in new/ and set the flags dirty in index file, but in that case
	   external MUAs would see wrong flags. */
	tmp_path = t_strconcat(ctx->tmpdir, "/", tmpname, NULL);
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
	if (rename(tmp_path, new_path) == 0)
		ret = 0;
	else {
		ret = -1;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(storage,
				MAIL_ERROR_NOSPACE, MAIL_ERRSTR_NO_SPACE);
		} else {
			mail_storage_set_critical(storage,
				"rename(%s, %s) failed: %m",
				tmp_path, new_path);
		}
	}
	return ret;
}

struct maildir_save_context *
maildir_save_transaction_init(struct maildir_transaction_context *t)
{
        struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;
	struct maildir_save_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("maildir_save_context", 4096);
	ctx = p_new(pool, struct maildir_save_context, 1);
	ctx->ctx.transaction = &t->ictx.mailbox_ctx;
	ctx->pool = pool;
	ctx->mbox = mbox;
	ctx->trans = t->ictx.trans;
	ctx->files_tail = &ctx->files;

	ctx->tmpdir = p_strconcat(pool, mbox->path, "/tmp", NULL);
	ctx->newdir = p_strconcat(pool, mbox->path, "/new", NULL);
	ctx->curdir = p_strconcat(pool, mbox->path, "/cur", NULL);

	ctx->keywords_buffer = buffer_create_const_data(pool, NULL, 0);
	array_create_from_buffer(&ctx->keywords_array, ctx->keywords_buffer,
				 sizeof(unsigned int));
	ctx->finished = TRUE;
	return ctx;
}

uint32_t maildir_save_add(struct maildir_transaction_context *t,
			  const char *base_fname, enum mail_flags flags,
			  struct mail_keywords *keywords,
			  struct mail *dest_mail)
{
	struct maildir_save_context *ctx = t->save_ctx;
	struct maildir_filename *mf;
	struct istream *input;

	/* now, we want to be able to rollback the whole append session,
	   so we'll just store the name of this temp file and move it later
	   into new/ or cur/. */
	/* @UNSAFE */
	mf = p_malloc(ctx->pool, sizeof(*mf) +
		      sizeof(unsigned int) * (keywords == NULL ? 0 :
					      keywords->count));
	mf->basename = p_strdup(ctx->pool, base_fname);
	mf->flags = flags;
	mf->size = (uoff_t)-1;
	mf->vsize = (uoff_t)-1;

	ctx->file_last = mf;
	i_assert(*ctx->files_tail == NULL);
	*ctx->files_tail = mf;
	ctx->files_tail = &mf->next;
	ctx->files_count++;

	if (keywords != NULL) {
		i_assert(sizeof(keywords->idx[0]) == sizeof(unsigned int));

		/* @UNSAFE */
		mf->keywords_count = keywords->count;
		memcpy(mf + 1, keywords->idx,
		       sizeof(unsigned int) * keywords->count);
		ctx->have_keywords = TRUE;
	}

	/* insert into index */
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE, flags);
	if (keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, keywords);
	}

	if (ctx->first_seq == 0) {
		ctx->first_seq = ctx->seq;
		i_assert(ctx->files->next == NULL);
	}

	if (dest_mail == NULL) {
		if (ctx->mail == NULL) {
			struct mailbox_transaction_context *_t =
				&t->ictx.mailbox_ctx;

			ctx->mail = mail_alloc(_t, 0, NULL);
		}
		dest_mail = ctx->mail;
	}
	mail_set_seq(dest_mail, ctx->seq);

	if (ctx->input == NULL) {
		/* FIXME: copying with hardlinking. we could copy the
		   cached data directly */
		ctx->cur_dest_mail = NULL;
	} else {
		input = index_mail_cache_parse_init(dest_mail, ctx->input);
		i_stream_unref(&ctx->input);
		ctx->input = input;
		ctx->cur_dest_mail = dest_mail;
	}
	return ctx->seq;
}

static bool
maildir_get_updated_filename(struct maildir_save_context *ctx,
			     struct maildir_filename *mf,
			     const char **fname_r)
{
	const char *basename = mf->basename;

	if (ctx->mbox->storage->save_size_in_filename &&
	    mf->size != (uoff_t)-1) {
		basename = t_strdup_printf("%s,%c=%"PRIuUOFF_T, basename,
					   MAILDIR_EXTRA_FILE_SIZE, mf->size);
	}

	/*if (mf->vsize != (uoff_t)-1) {
		basename = t_strdup_printf("%s,%c=%"PRIuUOFF_T, basename,
					   MAILDIR_EXTRA_VIRTUAL_SIZE,
					   mf->vsize);
	}*/

	if (mf->keywords_count == 0) {
		if ((mf->flags & MAIL_FLAGS_MASK) == MAIL_RECENT) {
			*fname_r = basename;
			return TRUE;
		}

		*fname_r = maildir_filename_set_flags(NULL, basename,
					mf->flags & MAIL_FLAGS_MASK, NULL);
		return FALSE;
	}

	buffer_update_const_data(ctx->keywords_buffer, mf + 1,
				 mf->keywords_count * sizeof(unsigned int));
	*fname_r = maildir_filename_set_flags(ctx->keywords_sync_ctx, basename,
					      mf->flags & MAIL_FLAGS_MASK,
					      &ctx->keywords_array);
	return FALSE;
}

static const char *maildir_mf_get_path(struct maildir_save_context *ctx,
				       struct maildir_filename *mf)
{
	const char *fname;

	if (!ctx->moving && (mf->flags & MAILDIR_SAVE_FLAG_HARDLINK) == 0) {
		/* file is still in tmp/ */
		return t_strdup_printf("%s/%s", ctx->tmpdir, mf->basename);
	}

	/* already moved to new/ or cur/ */
	if (maildir_get_updated_filename(ctx, mf, &fname))
		return t_strdup_printf("%s/%s", ctx->newdir, mf->basename);
	else
		return t_strdup_printf("%s/%s", ctx->curdir, fname);
}

const char *maildir_save_file_get_path(struct mailbox_transaction_context *_t,
				       uint32_t seq)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_save_context *ctx = t->save_ctx;
	struct maildir_filename *mf;

	i_assert(seq >= ctx->first_seq);

	seq -= ctx->first_seq;
	mf = ctx->files;
	while (seq > 0) {
		mf = mf->next;
		i_assert(mf != NULL);
		seq--;
	}

	return maildir_mf_get_path(ctx, mf);
}

static int maildir_create_tmp(struct maildir_mailbox *mbox, const char *dir,
			      const char **fname_r)
{
	struct mailbox *box = &mbox->ibox.box;
	struct stat st;
	unsigned int prefix_len;
	const char *tmp_fname = NULL;
	string_t *path;
	int fd;

	path = t_str_new(256);
	str_append(path, dir);
	str_append_c(path, '/');
	prefix_len = str_len(path);

	for (;;) {
		tmp_fname = maildir_filename_generate();
		str_truncate(path, prefix_len);
		str_append(path, tmp_fname);

		/* stat() first to see if it exists. pretty much the only
		   possibility of that happening is if time had moved
		   backwards, but even then it's highly unlikely. */
		if (stat(str_c(path), &st) == 0) {
			/* try another file name */
		} else if (errno != ENOENT) {
			mail_storage_set_critical(box->storage,
				"stat(%s) failed: %m", str_c(path));
			return -1;
		} else {
			/* doesn't exist */
			mode_t old_mask = umask(0777 & ~box->file_create_mode);
			fd = open(str_c(path),
				  O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0777);
			umask(old_mask);

			if (fd != -1 || errno != EEXIST)
				break;
			/* race condition between stat() and open().
			   highly unlikely. */
		}
	}

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
			mail_storage_set_critical(box->storage,
				"fchown(%s) failed: %m", str_c(path));
		}
	}

	return fd;
}

int maildir_save_init(struct mailbox_transaction_context *_t,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      time_t received_date, int timezone_offset ATTR_UNUSED,
		      const char *from_envelope ATTR_UNUSED,
		      struct istream *input, struct mail *dest_mail,
		      struct mail_save_context **ctx_r)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_save_context *ctx;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL)
		t->save_ctx = maildir_save_transaction_init(t);
	ctx = t->save_ctx;

	flags &= ~MAIL_RECENT;
	if (mbox->ibox.keep_recent)
		flags |= MAIL_RECENT;

	T_BEGIN {
		/* create a new file in tmp/ directory */
		const char *fname;

		ctx->fd = maildir_create_tmp(mbox, ctx->tmpdir, &fname);
		if (ctx->fd == -1)
			ctx->failed = TRUE;
		else {
			ctx->received_date = received_date;
			ctx->input = (ctx->mbox->storage->storage.flags &
				      MAIL_STORAGE_FLAG_SAVE_CRLF) != 0 ?
				i_stream_create_crlf(input) :
				i_stream_create_lf(input);

			maildir_save_add(t, fname, flags, keywords, dest_mail);
		}
	} T_END;
	if (ctx->failed)
		return -1;

	ctx->output = o_stream_create_fd_file(ctx->fd, 0, FALSE);
	o_stream_cork(ctx->output);

	*ctx_r = &ctx->ctx;
	return ctx->failed ? -1 : 0;
}

int maildir_save_continue(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;

	if (ctx->failed)
		return -1;

	do {
		if (o_stream_send_istream(ctx->output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_send_istream(%s/%s) "
					"failed: %m",
					ctx->tmpdir, ctx->file_last->basename);
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

static int maildir_save_finish_real(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	struct utimbuf buf;
	struct stat st;
	const char *path;
	int output_errno;

	ctx->finished = TRUE;
	if (ctx->failed && ctx->fd == -1) {
		/* tmp file creation failed */
		return -1;
	}

	path = t_strconcat(ctx->tmpdir, "/", ctx->file_last->basename, NULL);
	if (o_stream_flush(ctx->output) < 0) {
		mail_storage_set_critical(storage,
			"o_stream_flush(%s) failed: %m", path);
		ctx->failed = TRUE;
	}

	if (ctx->received_date != (time_t)-1) {
		/* set the received_date by modifying mtime */
		buf.actime = ioloop_time;
		buf.modtime = ctx->received_date;

		if (utime(path, &buf) < 0) {
			ctx->failed = TRUE;
			mail_storage_set_critical(storage,
						  "utime(%s) failed: %m", path);
		}
	} else if (ctx->fd != -1) {
		if (fstat(ctx->fd, &st) == 0)
			ctx->received_date = st.st_mtime;
		else {
			ctx->failed = TRUE;
			mail_storage_set_critical(storage,
						  "fstat(%s) failed: %m", path);
		}
	} else {
		/* hardlinked */
		if (stat(path, &st) == 0)
			ctx->received_date = st.st_mtime;
		else {
			ctx->failed = TRUE;
			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m", path);
		}
	}

	if (ctx->cur_dest_mail != NULL) {
		index_mail_cache_parse_deinit(ctx->cur_dest_mail,
					      ctx->received_date, !ctx->failed);
	}
	i_stream_unref(&ctx->input);

	/* remember the size in case we want to add it to filename */
	ctx->file_last->size = ctx->output->offset;
	if (ctx->cur_dest_mail == NULL ||
	    mail_get_virtual_size(ctx->cur_dest_mail,
				  &ctx->file_last->vsize) < 0)
		ctx->file_last->vsize = (uoff_t)-1;

	output_errno = ctx->output->stream_errno;
	o_stream_destroy(&ctx->output);

	if (!ctx->mbox->ibox.fsync_disable && !ctx->failed) {
		if (fsync(ctx->fd) < 0) {
			mail_storage_set_critical(storage,
						  "fsync(%s) failed: %m", path);
			ctx->failed = TRUE;
		}
	}
	if (close(ctx->fd) < 0) {
		mail_storage_set_critical(storage,
					  "close(%s) failed: %m", path);
		ctx->failed = TRUE;
	}
	ctx->fd = -1;

	if (ctx->failed) {
		struct maildir_filename **fm;

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
				"write(%s) failed: %m", ctx->mbox->path);
		}

		/* remove from the linked list */
		for (fm = &ctx->files; (*fm)->next != NULL; fm = &(*fm)->next) ;
		i_assert(*fm == ctx->file_last);
		*fm = NULL;
		ctx->files_tail = fm;
		ctx->file_last = NULL;
		ctx->files_count--;
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
	return ret;
}

void maildir_save_cancel(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)maildir_save_finish(_ctx);
}

static void
maildir_transaction_unlink_copied_files(struct maildir_save_context *ctx,
					struct maildir_filename *pos)
{
	struct maildir_filename *mf;

	/* try to unlink the mails already moved */
	for (mf = ctx->files; mf != pos; mf = mf->next) {
		if ((mf->flags & MAILDIR_SAVE_FLAG_DELETED) == 0) {
			T_BEGIN {
				(void)unlink(maildir_mf_get_path(ctx, mf));
			} T_END;
		}
	}
	ctx->files = pos;
}

int maildir_transaction_save_commit_pre(struct maildir_save_context *ctx)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)ctx->ctx.transaction;
	struct maildir_filename *mf;
	uint32_t seq, uid, first_uid, next_uid;
	enum maildir_uidlist_rec_flag flags;
	bool newdir, sync_commit = FALSE;
	int ret;

	i_assert(ctx->output == NULL);
	i_assert(ctx->finished);

	/* if we want to assign UIDs or keywords, we require uidlist lock */
	if ((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS) == 0 &&
	    !ctx->have_keywords) {
		/* assign the UIDs if we happen to get a lock */
		ctx->locked = maildir_uidlist_try_lock(ctx->mbox->uidlist) > 0;
	} else {
		if (maildir_uidlist_lock(ctx->mbox->uidlist) <= 0) {
			/* error or timeout - our transaction is broken */
			maildir_transaction_save_rollback(ctx);
			return -1;
		}
		ctx->locked = TRUE;
	}

	if (ctx->locked) {
		ret = maildir_uidlist_sync_init(ctx->mbox->uidlist,
						MAILDIR_UIDLIST_SYNC_PARTIAL,
						&ctx->uidlist_sync_ctx);
		i_assert(ret > 0); /* already locked, shouldn't fail */

		if (maildir_sync_index_begin(ctx->mbox, NULL,
					     &ctx->sync_ctx) < 0) {
			maildir_transaction_save_rollback(ctx);
			return -1;
		}

		ctx->keywords_sync_ctx =
			maildir_sync_get_keywords_sync_ctx(ctx->sync_ctx);

		/* now that uidlist is locked, make sure all the existing mails
		   have been added to index. we don't really look into the
		   maildir, just add all the new mails listed in
		   dovecot-uidlist to index. */
		if (maildir_sync_index(ctx->sync_ctx, TRUE) < 0) {
			maildir_transaction_save_rollback(ctx);
			return -1;
		}
		sync_commit = TRUE;

		/* if messages were added to index, assign them UIDs */
		first_uid = maildir_uidlist_get_next_uid(ctx->mbox->uidlist);
		i_assert(first_uid != 0);
		mail_index_append_assign_uids(ctx->trans, first_uid, &next_uid);
		i_assert(next_uid = first_uid + ctx->files_count);

		/* these mails are all recent in our session */
		for (uid = first_uid; uid < next_uid; uid++)
			index_mailbox_set_recent_uid(&ctx->mbox->ibox, uid);

		if (!ctx->mbox->ibox.keep_recent) {
			/* maildir_sync_index() dropped recent flags from
			   existing messages. we'll still need to drop recent
			   flags from these newly added messages. */
			mail_index_update_header(ctx->trans,
				offsetof(struct mail_index_header,
					 first_recent_uid),
				&next_uid, sizeof(next_uid), FALSE);
		}

		/* this will work even if index isn't updated */
		*t->ictx.first_saved_uid = first_uid;
		*t->ictx.last_saved_uid = next_uid - 1;
	} else {
		/* since we couldn't lock uidlist, we'll have to drop the
		   appends to index. */
		for (seq = ctx->seq; seq >= ctx->first_seq; seq--)
			mail_index_expunge(ctx->trans, seq);

		mail_cache_transaction_rollback(&t->ictx.cache_trans);
		t->ictx.cache_trans =
			mail_cache_get_transaction(t->ictx.cache_view,
						   t->ictx.trans);
	}

	/* move them into new/ and/or cur/ */
	ret = 0;
	ctx->moving = TRUE;
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		T_BEGIN {
			const char *dest;

			newdir = maildir_get_updated_filename(ctx, mf, &dest);

			/* if hardlink-flag is set, the file is already in
			   destination. if the hardlinked mail contained
			   keywords, it was linked into tmp/ and it doesn't
			   have the hardlink-flag set, so it's treated as any
			   other saved mail. */
			if ((mf->flags & MAILDIR_SAVE_FLAG_HARDLINK) != 0)
				ret = 0;
			else {
				ret = maildir_file_move(ctx, mf->basename,
							dest, newdir);
			}
		} T_END;
		if (ret < 0)
			break;
	}

	if (ret == 0 && ctx->uidlist_sync_ctx != NULL) {
		/* everything was moved successfully. update our internal
		   state. */
		for (mf = ctx->files; mf != NULL; mf = mf->next) T_BEGIN {
			const char *dest;
			newdir = maildir_get_updated_filename(ctx, mf, &dest);

			flags = MAILDIR_UIDLIST_REC_FLAG_RECENT;
			if (newdir)
				flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
			ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
							dest, flags);
			i_assert(ret > 0);
		} T_END;
	}

	if (ctx->uidlist_sync_ctx != NULL) {
		/* update dovecot-uidlist file. */
		if (maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx) < 0)
			ret = -1;
	}

	*t->ictx.saved_uid_validity =
		maildir_uidlist_get_uid_validity(ctx->mbox->uidlist);

	if (ctx->mail != NULL) {
		/* Mail freeing may trigger cache updates and a call to
		   maildir_save_file_get_path(). Do this before finishing index
		   sync so we still have keywords_sync_ctx. */
		mail_free(&ctx->mail);
	}

	if (sync_commit) {
		/* It doesn't matter if index syncing fails */
		ctx->keywords_sync_ctx = NULL;
		(void)maildir_sync_index_finish(&ctx->sync_ctx,
						ret < 0, !sync_commit);
	}

	if (ret < 0) {
		ctx->keywords_sync_ctx = !ctx->have_keywords ? NULL :
			maildir_keywords_sync_init(ctx->mbox->keywords,
						   ctx->mbox->ibox.index);

		/* unlink the files we just moved in an attempt to rollback
		   the transaction. uidlist is still locked, so at least other
		   Dovecot instances haven't yet seen the files. */
		maildir_transaction_unlink_copied_files(ctx, mf);

		if (ctx->keywords_sync_ctx != NULL)
			maildir_keywords_sync_deinit(&ctx->keywords_sync_ctx);
		/* returning failure finishes the save_context */
		maildir_transaction_save_rollback(ctx);
		return -1;
	}
	return ret;
}

void maildir_transaction_save_commit_post(struct maildir_save_context *ctx)
{
	ctx->ctx.transaction = NULL; /* transaction is already freed */

	if (ctx->locked)
		maildir_uidlist_unlock(ctx->mbox->uidlist);
	pool_unref(&ctx->pool);
}

static void
maildir_transaction_save_rollback_real(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	string_t *str;
	size_t dir_len;
	bool hardlinks = FALSE;

	i_assert(ctx->output == NULL);

	if (!ctx->finished)
		maildir_save_cancel(&ctx->ctx);

	str = t_str_new(1024);
	str_append(str, ctx->tmpdir);
	str_append_c(str, '/');
        dir_len = str_len(str);

	/* clean up the temp files */
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		if ((mf->flags & MAILDIR_SAVE_FLAG_HARDLINK) == 0) {
			mf->flags |= MAILDIR_SAVE_FLAG_DELETED;
			str_truncate(str, dir_len);
			str_append(str, mf->basename);
			(void)unlink(str_c(str));
		} else {
			hardlinks = TRUE;
		}
	}

	if (hardlinks)
		maildir_transaction_unlink_copied_files(ctx, NULL);

	if (ctx->uidlist_sync_ctx != NULL)
		(void)maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx);
	if (ctx->locked)
		maildir_uidlist_unlock(ctx->mbox->uidlist);
	if (ctx->sync_ctx != NULL)
		(void)maildir_sync_index_finish(&ctx->sync_ctx, TRUE, FALSE);

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
	pool_unref(&ctx->pool);
}

void maildir_transaction_save_rollback(struct maildir_save_context *ctx)
{
	T_BEGIN {
		maildir_transaction_save_rollback_real(ctx);
	} T_END;
}
