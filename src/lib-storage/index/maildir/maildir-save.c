/* Copyright (C) 2002-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "ostream.h"
#include "ostream-crlf.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

struct maildir_filename {
	struct maildir_filename *next;
	const char *basename;

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

	const char *tmpdir, *newdir, *curdir;
	struct maildir_filename *files;

	buffer_t *keywords_buffer;
	array_t ARRAY_DEFINE(keywords_array, unsigned int);

	struct istream *input;
	struct ostream *output;
	int fd;
	time_t received_date;
	uint32_t seq;

	unsigned int synced:1;
	unsigned int failed:1;
};

static int maildir_file_move(struct maildir_save_context *ctx,
			     const char *basename, const char *dest)
{
	const char *tmp_path, *new_path;
	int ret;

	t_push();

	/* if we have flags, we'll move it to cur/ directly, because files in
	   new/ directory can't have flags. alternative would be to write it
	   in new/ and set the flags dirty in index file, but in that case
	   external MUAs would see wrong flags. */
	tmp_path = t_strconcat(ctx->tmpdir, "/", basename, NULL);
	new_path = dest == NULL ?
		t_strconcat(ctx->newdir, "/", basename, NULL) :
		t_strconcat(ctx->curdir, "/", dest, NULL);

	if (link(tmp_path, new_path) == 0)
		ret = 0;
	else {
		ret = -1;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(STORAGE(ctx->mbox->storage),
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
				"link(%s, %s) failed: %m", tmp_path, new_path);
		}
	}

	if (unlink(tmp_path) < 0 && errno != ENOENT) {
		mail_storage_set_critical(STORAGE(ctx->mbox->storage),
			"unlink(%s) failed: %m", tmp_path);
	}
	t_pop();
	return ret;
}

static struct maildir_save_context *
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

	ctx->tmpdir = p_strconcat(pool, mbox->path, "/tmp", NULL);
	ctx->newdir = p_strconcat(pool, mbox->path, "/new", NULL);
	ctx->curdir = p_strconcat(pool, mbox->path, "/cur", NULL);

	ctx->synced = maildir_sync_is_synced(mbox) > 0;

	ctx->keywords_buffer = buffer_create_const_data(pool, NULL, 0);
	array_create_from_buffer(&ctx->keywords_array, ctx->keywords_buffer,
				 sizeof(unsigned int));
	return ctx;
}

struct mail_save_context *
maildir_save_init(struct mailbox_transaction_context *_t,
		  enum mail_flags flags, struct mail_keywords *keywords,
		  time_t received_date, int timezone_offset __attr_unused__,
		  const char *from_envelope __attr_unused__,
		  struct istream *input, int want_mail)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_save_context *ctx;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;
	struct maildir_filename *mf;
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
		return &ctx->ctx;
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
	o_stream_unref(output);

	flags &= ~MAIL_RECENT;
	if (mbox->ibox.keep_recent)
		flags |= MAIL_RECENT;

	/* now, we want to be able to rollback the whole append session,
	   so we'll just store the name of this temp file and move it later
	   into new/ or cur/. */
	/* @UNSAFE */
	mf = p_malloc(ctx->pool, sizeof(*mf) +
		      sizeof(unsigned int) * (keywords == NULL ? 0 :
					      keywords->count));
	mf->next = ctx->files;
	mf->basename = p_strdup(ctx->pool, fname);
	mf->flags = flags;
	ctx->files = mf;

	if (keywords != NULL) {
		i_assert(sizeof(keywords->idx[0]) == sizeof(unsigned int));

		/* @UNSAFE */
		mf->keywords_count = keywords->count;
		memcpy(mf + 1, keywords->idx,
		       sizeof(unsigned int) * keywords->count);
	}

	if (!ctx->synced && want_mail) {
		if (maildir_storage_sync_force(mbox) < 0)
			ctx->failed = TRUE;
		else
			ctx->synced = TRUE;
	}

	if (ctx->synced) {
		/* insert into index */
		mail_index_append(ctx->trans, 0, &ctx->seq);
		mail_index_update_flags(ctx->trans, ctx->seq,
					MODIFY_REPLACE, flags);
		if (keywords != NULL) {
			mail_index_update_keywords(ctx->trans, ctx->seq,
						   MODIFY_REPLACE, keywords);
		}
	}
	t_pop();

	ctx->failed = FALSE;
	return &ctx->ctx;
}

int maildir_save_continue(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	if (ctx->failed)
		return -1;

	if (o_stream_send_istream(ctx->output, ctx->input) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

int maildir_save_finish(struct mail_save_context *_ctx, struct mail *dest_mail)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;
	struct utimbuf buf;
	const char *path;
	int output_errno;

	if (ctx->failed && ctx->fd == -1) {
		/* tmp file creation failed */
		return -1;
	}

	t_push();
	path = t_strconcat(ctx->tmpdir, "/", ctx->files->basename, NULL);

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
	o_stream_unref(ctx->output);
	ctx->output = NULL;

	/* FIXME: when saving multiple messages, we could get better
	   performance if we left the fd open and fsync()ed it later */
	if (fsync(ctx->fd) < 0) {
		mail_storage_set_critical(STORAGE(ctx->mbox->storage),
					  "fsync(%s) failed: %m", path);
		ctx->failed = TRUE;
	}
	if (close(ctx->fd) < 0) {
		mail_storage_set_critical(STORAGE(ctx->mbox->storage),
					  "close(%s) failed: %m", path);
		ctx->failed = TRUE;
	}
	ctx->fd = -1;

	if (ctx->failed) {
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

		ctx->files = ctx->files->next;
		t_pop();
		return -1;
	}

	if (dest_mail != NULL) {
		i_assert(ctx->seq != 0);

		if (mail_set_seq(dest_mail, ctx->seq) < 0)
			return -1;
	}

	t_pop();
	return 0;
}

void maildir_save_cancel(struct mail_save_context *_ctx)
{
	struct maildir_save_context *ctx = (struct maildir_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)maildir_save_finish(_ctx, NULL);
}

static const char *
maildir_get_updated_filename(struct maildir_save_context *ctx,
			     struct maildir_index_sync_context *sync_ctx,
			     struct maildir_filename *mf)
{
	if (mf->flags == MAIL_RECENT && mf->keywords_count == 0)
		return NULL;

	buffer_update_const_data(ctx->keywords_buffer, mf + 1,
				 mf->keywords_count * sizeof(unsigned int));
	return maildir_filename_set_flags(sync_ctx, mf->basename,
					  mf->flags, &ctx->keywords_array);
}

static void
maildir_save_commit_abort(struct maildir_save_context *ctx,
			  struct maildir_index_sync_context *sync_ctx,
			  struct maildir_filename *pos)
{
	struct maildir_filename *mf;
	const char *path, *dest;

	/* try to unlink the mails already moved */
	for (mf = ctx->files; mf != pos; mf = mf->next) {
		t_push();
		dest = maildir_get_updated_filename(ctx, sync_ctx, mf);
		if (dest != NULL)
			path = t_strdup_printf("%s/%s", ctx->curdir, dest);
		else {
			path = t_strdup_printf("%s/%s",
					       ctx->newdir, mf->basename);
		}
		(void)unlink(path);
	}
	ctx->files = pos;

	maildir_transaction_save_rollback(ctx);
}

int maildir_transaction_save_commit_pre(struct maildir_save_context *ctx)
{
	struct maildir_index_sync_context *sync_ctx;
	struct maildir_filename *mf;
	uint32_t first_uid, last_uid;
	enum maildir_uidlist_rec_flag flags;
	const char *dest, *fname;
	int ret;

	i_assert(ctx->output == NULL);

	sync_ctx = maildir_sync_index_begin(ctx->mbox);
	if (sync_ctx == NULL) {
		maildir_save_commit_abort(ctx, sync_ctx, ctx->files);
		return -1;
	}

	ret = maildir_uidlist_lock(ctx->mbox->uidlist);
	if (ret <= 0) {
		/* error or timeout - our transaction is broken */
		maildir_sync_index_abort(sync_ctx);
		maildir_save_commit_abort(ctx, sync_ctx, ctx->files);
		return -1;
	}

	if (ctx->synced) {
		first_uid = maildir_uidlist_get_next_uid(ctx->mbox->uidlist);
		mail_index_append_assign_uids(ctx->trans, first_uid, &last_uid);
	}

	flags = MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
		MAILDIR_UIDLIST_REC_FLAG_RECENT;

	/* move them into new/ */
	ctx->uidlist_sync_ctx =
		maildir_uidlist_sync_init(ctx->mbox->uidlist, TRUE);

	ret = 0;
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		t_push();
		dest = maildir_get_updated_filename(ctx, sync_ctx, mf);
		fname = dest != NULL ? dest : mf->basename;

		if (maildir_file_move(ctx, mf->basename, dest) < 0 ||
		    maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
					      fname, flags) < 0) {
			maildir_save_commit_abort(ctx, sync_ctx, mf);
			t_pop();
			ret = -1;
			break;
		}
		t_pop();
	}

	if (ret == 0) {
		/* finish uidlist syncing, but keep it still locked */
		maildir_uidlist_sync_finish(ctx->uidlist_sync_ctx);
	}

	if (ret < 0) {
		/* deinit only if we failed. otherwise save_commit_post()
		   does it. */
		if (maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx) < 0)
			ret = -1;
		ctx->uidlist_sync_ctx = NULL;
	}

	maildir_sync_index_abort(sync_ctx);
	return ret;
}

void maildir_transaction_save_commit_post(struct maildir_save_context *ctx)
{
	/* can't do anything anymore if we fail */
	(void)maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);

	pool_unref(ctx->pool);
}

void maildir_transaction_save_rollback(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	string_t *str;

	i_assert(ctx->output == NULL);

	t_push();
	str = t_str_new(1024);

	/* clean up the temp files */
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		str_truncate(str, 0);
		str_printfa(str, "%s/%s", ctx->tmpdir, mf->basename);
		(void)unlink(str_c(str));
	}
	t_pop();

	pool_unref(ctx->pool);
}
