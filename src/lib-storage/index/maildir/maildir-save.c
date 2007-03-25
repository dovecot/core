/* Copyright (C) 2002-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "istream-tee.h"
#include "ostream.h"
#include "ostream-crlf.h"
#include "str.h"
#include "index-mail.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
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

	uoff_t size;
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
	struct maildir_index_sync_context *sync_ctx;
	struct mail *mail, *cur_dest_mail;

	const char *tmpdir, *newdir, *curdir;
	struct maildir_filename *files, **files_tail, *file_last;

	buffer_t *keywords_buffer;
	ARRAY_TYPE(keyword_indexes) keywords_array;

	struct istream *input, *input2;
	struct ostream *output;
	int fd;
	time_t received_date;
	uint32_t first_seq, seq;

	unsigned int want_mails:1;
	unsigned int failed:1;
	unsigned int moving:1;
	unsigned int finished:1;
};

static int maildir_file_move(struct maildir_save_context *ctx,
			     const char *tmpname, const char *destname,
			     bool newdir)
{
	struct mail_storage *storage = STORAGE(ctx->mbox->storage);
	const char *tmp_path, *new_path;
	int ret;

	t_push();

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
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(storage,
				"rename(%s, %s) failed: %m",
				tmp_path, new_path);
		}
	}
	t_pop();
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

	/* we'll do a quick check here to see if maildir is currently in
	   synced state. in that case it's cheap to update index file.
	   this can't be completely trusted because uidlist isn't locked,
	   but if there are some changes we can deal with it. */
	ctx->want_mails = maildir_sync_is_synced(mbox);

	ctx->keywords_buffer = buffer_create_const_data(pool, NULL, 0);
	array_create_from_buffer(&ctx->keywords_array, ctx->keywords_buffer,
				 sizeof(unsigned int));
	ctx->finished = TRUE;
	return ctx;
}

static void maildir_save_add_existing_to_index(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	struct mail_keywords *kw;
	uint32_t seq;

	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		mail_index_append(ctx->trans, 0, &seq);
		mail_index_update_flags(ctx->trans, seq,
					MODIFY_REPLACE, mf->flags);
		if (mf->keywords_count != 0) {
			t_push();
			/* @UNSAFE */
			kw = t_malloc(sizeof(*kw) + sizeof(kw->idx[0]) *
				      mf->keywords_count);
			memcpy(kw->idx, mf + 1, sizeof(kw->idx[0]) *
			       mf->keywords_count);
			mail_index_update_keywords(ctx->trans, ctx->seq,
						   MODIFY_REPLACE, kw);
			t_pop();
		}
	}
}

uint32_t maildir_save_add(struct maildir_transaction_context *t,
			  const char *base_fname, enum mail_flags flags,
			  struct mail_keywords *keywords,
			  struct mail *dest_mail)
{
	struct maildir_save_context *ctx = t->save_ctx;
	struct maildir_filename *mf;
	struct tee_istream *tee;

	if (dest_mail != NULL && !ctx->want_mails) {
		ctx->want_mails = TRUE;
		/* if there are any existing mails, we need to append them
		   to index here to keep the UIDs correct */
		maildir_save_add_existing_to_index(ctx);
	}

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

	ctx->file_last = mf;
	i_assert(*ctx->files_tail == NULL);
	*ctx->files_tail = mf;
	ctx->files_tail = &mf->next;

	if (keywords != NULL) {
		i_assert(sizeof(keywords->idx[0]) == sizeof(unsigned int));

		/* @UNSAFE */
		mf->keywords_count = keywords->count;
		memcpy(mf + 1, keywords->idx,
		       sizeof(unsigned int) * keywords->count);
	}

	if (ctx->want_mails) {
		/* insert into index */
		mail_index_append(ctx->trans, 0, &ctx->seq);
		mail_index_update_flags(ctx->trans, ctx->seq,
					MODIFY_REPLACE, flags);
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

				ctx->mail = index_mail_alloc(_t, 0, NULL);
			}
			dest_mail = ctx->mail;
		}
		if (mail_set_seq(dest_mail, ctx->seq) < 0)
			i_unreached();

		if (ctx->input == NULL) {
			/* FIXME: copying with hardlinking. we could copy the
			   cached data directly */
			ctx->cur_dest_mail = 0;
		} else {
			tee = tee_i_stream_create(ctx->input, default_pool);
			ctx->input =
				tee_i_stream_create_child(tee, default_pool);
			ctx->input2 =
				tee_i_stream_create_child(tee, default_pool);

			index_mail_cache_parse_init(dest_mail, ctx->input2);
			ctx->cur_dest_mail = dest_mail;
		}
	} else {
		ctx->seq = 0;
		ctx->cur_dest_mail = NULL;
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
		basename = t_strdup_printf("%s,S=%"PRIuUOFF_T,
					   basename, mf->size);
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

	buffer_update_const_data(ctx->keywords_buffer, mf + 1,
				 mf->keywords_count * sizeof(unsigned int));
	*fname_r = maildir_filename_set_flags(
			maildir_sync_get_keywords_sync_ctx(ctx->sync_ctx),
			basename, mf->flags & MAIL_FLAGS_MASK,
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

int maildir_save_init(struct mailbox_transaction_context *_t,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      time_t received_date, int timezone_offset __attr_unused__,
		      const char *from_envelope __attr_unused__,
		      struct istream *input, struct mail *dest_mail,
		      struct mail_save_context **ctx_r)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_save_context *ctx;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;
	struct ostream *output;
	const char *fname, *path;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	t_push();

	if (t->save_ctx == NULL)
		t->save_ctx = maildir_save_transaction_init(t);
	ctx = t->save_ctx;

	/* create a new file in tmp/ directory */
	ctx->fd = maildir_create_tmp(mbox, ctx->tmpdir, mbox->mail_create_mode,
				     &path);
	if (ctx->fd == -1) {
		ctx->failed = TRUE;
		t_pop();
		return -1;
	}

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	fname++;

	ctx->received_date = received_date;
	ctx->input = input;

	output = o_stream_create_file(ctx->fd, system_pool, 0, FALSE);
	ctx->output = (STORAGE(ctx->mbox->storage)->flags &
		       MAIL_STORAGE_FLAG_SAVE_CRLF) != 0 ?
		o_stream_create_crlf(default_pool, output) :
		o_stream_create_lf(default_pool, output);
	o_stream_unref(&output);

	flags &= ~MAIL_RECENT;
	if (mbox->ibox.keep_recent)
		flags |= MAIL_RECENT;

	maildir_save_add(t, fname, flags, keywords, dest_mail);

	t_pop();
	*ctx_r = &ctx->ctx;
	return ctx->failed ? -1 : 0;
}

int maildir_save_continue(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	if (ctx->failed)
		return -1;

	if (ctx->cur_dest_mail != NULL)
		index_mail_cache_parse_continue(ctx->cur_dest_mail);

	if (o_stream_send_istream(ctx->output, ctx->input) < 0) {
		if (ENOSPACE(errno)) {
			mail_storage_set_error(STORAGE(ctx->mbox->storage),
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
				"o_stream_send_istream(%s/%s) failed: %m",
				ctx->tmpdir, ctx->file_last->basename);
		}
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

int maildir_save_finish(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct utimbuf buf;
	const char *path;
	int output_errno;

	if (ctx->cur_dest_mail != NULL) {
		index_mail_cache_parse_deinit(ctx->cur_dest_mail);
		i_stream_unref(&ctx->input);
		i_stream_unref(&ctx->input2);
	}

	ctx->finished = TRUE;
	if (ctx->failed && ctx->fd == -1) {
		/* tmp file creation failed */
		return -1;
	}

	/* remember the size in case we want to add it to filename */
	ctx->file_last->size = ctx->output->offset;

	t_push();
	path = t_strconcat(ctx->tmpdir, "/", ctx->file_last->basename, NULL);

	if (ctx->received_date != (time_t)-1) {
		/* set the received_date by modifying mtime */
		buf.actime = ioloop_time;
		buf.modtime = ctx->received_date;

		if (utime(path, &buf) < 0) {
			ctx->failed = TRUE;
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
						  "utime(%s) failed: %m", path);
		}
	}

	output_errno = ctx->output->stream_errno;
	o_stream_destroy(&ctx->output);

	if (!ctx->mbox->ibox.fsync_disable) {
		if (fsync(ctx->fd) < 0) {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
						  "fsync(%s) failed: %m", path);
			ctx->failed = TRUE;
		}
	}
	if (close(ctx->fd) < 0) {
		mail_storage_set_critical(STORAGE(ctx->mbox->storage),
					  "close(%s) failed: %m", path);
		ctx->failed = TRUE;
	}
	ctx->fd = -1;

	if (ctx->failed) {
		struct maildir_filename **fm;

		/* delete the tmp file */
		if (unlink(path) < 0 && errno != ENOENT) {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
				"unlink(%s) failed: %m", path);
		}

		errno = output_errno;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(STORAGE(ctx->mbox->storage),
					       "Not enough disk space");
		} else if (errno != 0) {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
				"write(%s) failed: %m", ctx->mbox->path);
		}

		/* remove from the linked list */
		for (fm = &ctx->files; (*fm)->next != NULL; fm = &(*fm)->next) ;
		i_assert(*fm == ctx->file_last);
		*fm = NULL;
		ctx->files_tail = fm;
		ctx->file_last = NULL;

		t_pop();
		return -1;
	}
	t_pop();

	ctx->file_last = NULL;
	return 0;
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
		if ((mf->flags & MAILDIR_SAVE_FLAG_DELETED) != 0)
			continue;

		t_push();
		(void)unlink(maildir_mf_get_path(ctx, mf));
		t_pop();
	}
	ctx->files = pos;
}

int maildir_transaction_save_commit_pre(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	uint32_t first_uid, next_uid;
	enum maildir_uidlist_rec_flag flags;
	const char *dest;
	bool newdir, sync_commit = FALSE;
	int ret;

	i_assert(ctx->output == NULL);
	i_assert(ctx->finished);

	if (maildir_uidlist_sync_init(ctx->mbox->uidlist, TRUE,
				      &ctx->uidlist_sync_ctx) <= 0) {
		/* error or timeout - our transaction is broken */
		maildir_transaction_save_rollback(ctx);
		return -1;
	}

	/* Start syncing so that keywords_sync_ctx gets set.. */
	if (maildir_sync_index_begin(ctx->mbox, &ctx->sync_ctx) < 0) {
		maildir_transaction_save_rollback(ctx);
		return -1;
	}

	if (ctx->want_mails) {
		/* now that uidlist is locked, make sure all the existing mails
		   have been added to index. we don't really look into the
		   maildir, just add all the new mails listed in
		   dovecot-uidlist to index. */
		if (maildir_sync_index(ctx->sync_ctx, TRUE) < 0) {
			maildir_transaction_save_rollback(ctx);
			return -1;
		}
		sync_commit = TRUE;

		first_uid = maildir_uidlist_get_next_uid(ctx->mbox->uidlist);
		i_assert(first_uid != 0);
		mail_index_append_assign_uids(ctx->trans, first_uid, &next_uid);
	}

	flags = MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
		MAILDIR_UIDLIST_REC_FLAG_RECENT;

	/* move them into new/ and/or cur/ */
	ret = 0;
	ctx->moving = TRUE;
	for (mf = ctx->files; mf != NULL && ret == 0; mf = mf->next) {
		t_push();
		newdir = maildir_get_updated_filename(ctx, mf, &dest);

		/* if hardlink-flag is set, the file is already in destination.
		   if the hardlinked mail contained keywords, it was linked
		   into tmp/ and it doesn't have the hardlink-flag set, so it's
		   treated as any other saved mail. */
		if ((mf->flags & MAILDIR_SAVE_FLAG_HARDLINK) == 0) {
			ret = maildir_file_move(ctx, mf->basename,
						dest, newdir);
		}
		if (ret == 0) {
			ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
							dest, flags);
			i_assert(ret != 0);
			ret = ret < 0 ? -1 : 0;
		}
		t_pop();
	}

	/* if we didn't call maildir_sync_index() we could skip over
	   transactions by committing the changes */
	if (maildir_sync_index_finish(&ctx->sync_ctx, ret < 0,
				      !sync_commit) < 0)
		ret = -1;

	if (ret < 0) {
		/* unlink the files we just moved in an attempt to rollback
		   the transaction. uidlist is still locked, so at least other
		   Dovecot instances haven't yet seen the files. */
		maildir_transaction_unlink_copied_files(ctx, mf);

		/* returning failure finishes the save_context */
		maildir_transaction_save_rollback(ctx);
	}

	return ret;
}

void maildir_transaction_save_commit_post(struct maildir_save_context *ctx)
{
	/* uidlist locks the syncing. don't release it until save's transaction
	   has been written to disk. */
	(void)maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx);

	if (ctx->mail != NULL)
		index_mail_free(ctx->mail);
	pool_unref(ctx->pool);
}

void maildir_transaction_save_rollback(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	string_t *str;
	size_t dir_len;
	bool hardlinks = FALSE;

	i_assert(ctx->output == NULL);

	if (!ctx->finished)
		maildir_save_cancel(&ctx->ctx);

	t_push();
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
	if (ctx->sync_ctx != NULL)
		(void)maildir_sync_index_finish(&ctx->sync_ctx, TRUE, FALSE);

	t_pop();

	if (ctx->mail != NULL)
		index_mail_free(ctx->mail);
	pool_unref(ctx->pool);
}
