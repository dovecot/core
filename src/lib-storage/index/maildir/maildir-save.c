/* Copyright (C) 2002-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "maildir-storage.h"
#include "mail-save.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

struct maildir_filename {
	struct maildir_filename *next;
	const char *src, *dest;
};

struct maildir_save_context {
	pool_t pool;

	struct index_mailbox *ibox;

	const char *tmpdir, *newdir;
	struct maildir_filename *files;
};

static const char *
maildir_read_into_tmp(struct index_mailbox *ibox, const char *dir,
		      struct istream *input)
{
	const char *path, *fname;
	struct ostream *output;
	int fd;

	fd = maildir_create_tmp(ibox, dir, ibox->mail_create_mode, &path);
	if (fd == -1)
		return NULL;

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	fname++;

	output = o_stream_create_file(fd, pool_datastack_create(), 4096, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	if (mail_storage_save(ibox->box.storage, path, input, output,
			      getenv("MAIL_SAVE_CRLF") != NULL, NULL, NULL) < 0)
		fname = NULL;

	o_stream_unref(output);
	/* FIXME: when saving multiple messages, we could get better
	   performance if we left the fd open and fsync()ed it later */
	if (fsync(fd) < 0) {
		mail_storage_set_critical(ibox->box.storage,
					  "fsync() failed for %s: %m", path);
		fname = NULL;
	}
	if (close(fd) < 0) {
		mail_storage_set_critical(ibox->box.storage,
					  "close() failed for %s: %m", path);
		fname = NULL;
	}

	if (fname == NULL)
		(void)unlink(path);
	return fname;
}

static int maildir_file_move(struct maildir_save_context *ctx,
			     const char *src, const char *dest)
{
	const char *tmp_path, *new_path;
	int ret;

	t_push();

	tmp_path = t_strconcat(ctx->tmpdir, "/", src, NULL);
	new_path = t_strconcat(ctx->newdir, "/", dest, NULL);

	if (link(tmp_path, new_path) == 0)
		ret = 0;
	else {
		ret = -1;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(ctx->ibox->box.storage,
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(ctx->ibox->box.storage,
				"link(%s, %s) failed: %m", tmp_path, new_path);
		}
	}

	if (unlink(tmp_path) < 0 && errno != ENOENT) {
		mail_storage_set_critical(ctx->ibox->box.storage,
			"unlink(%s) failed: %m", tmp_path);
	}
	t_pop();
	return ret;
}

static struct maildir_save_context *
mailbox_save_init(struct index_mailbox *ibox)
{
	struct maildir_save_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("maildir_save_context", 4096);
	ctx = p_new(pool, struct maildir_save_context, 1);
	ctx->pool = pool;
	ctx->ibox = ibox;

	ctx->tmpdir = p_strconcat(pool, ibox->path, "/tmp", NULL);
	ctx->newdir = p_strconcat(pool, ibox->path, "/new", NULL);
	return ctx;
}

int maildir_save(struct mailbox_transaction_context *_t,
		 const struct mail_full_flags *flags,
		 time_t received_date, int timezone_offset __attr_unused__,
		 const char *from_envelope __attr_unused__,
		 struct istream *data)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_save_context *ctx;
	struct index_mailbox *ibox = t->ictx.ibox;
	struct maildir_filename *mf;
	enum mail_flags mail_flags;
        struct utimbuf buf;
	const char *fname, *dest_fname, *tmp_path;

	if (t->save_ctx == NULL)
		t->save_ctx = mailbox_save_init(ibox);
	ctx = t->save_ctx;

	mail_flags = flags->flags;
	/*FIXME:if (!index_mailbox_fix_keywords(ibox, &mail_flags,
					    flags->keywords,
					    flags->keywords_count))
		return FALSE;*/

	t_push();

	/* create the file into tmp/ directory */
	fname = maildir_read_into_tmp(ibox, ctx->tmpdir, data);
	if (fname == NULL) {
		t_pop();
		return -1;
	}

	tmp_path = t_strconcat(ctx->tmpdir, "/", fname, NULL);

	if (received_date != (time_t)-1) {
		/* set the received_date by modifying mtime */
		buf.actime = ioloop_time;
		buf.modtime = received_date;
		if (utime(tmp_path, &buf) < 0) {
			mail_storage_set_critical(ibox->box.storage,
				"utime(%s) failed: %m", tmp_path);
			t_pop();
			return -1;
		}
	}

	/* now, we want to be able to rollback the whole append session,
	   so we'll just store the name of this temp file and move it later
	   into new/ */
	dest_fname = mail_flags == 0 ? fname :
		maildir_filename_set_flags(fname, mail_flags, NULL);

	mf = p_new(ctx->pool, struct maildir_filename, 1);
	mf->next = ctx->files;
	mf->src = p_strdup(ctx->pool, fname);
	mf->dest = p_strdup(ctx->pool, dest_fname);
	ctx->files = mf;

	t_pop();
	return 0;
}

int maildir_save_commit(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf, *mf2;
	const char *path;
	int ret = 0;

	/* move them into new/ */
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		if (maildir_file_move(ctx, mf->src, mf->dest) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret < 0) {
		/* failed, try to unlink the mails already moved */
		for (mf2 = ctx->files; mf2 != mf; mf2 = mf2->next) {
			t_push();
			path = t_strconcat(ctx->newdir, "/",
					   mf2->dest, NULL);
			(void)unlink(path);
			t_pop();
		}
	}

	pool_unref(ctx->pool);
	return ret;
}

void maildir_save_rollback(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	const char *path;

	/* clean up the temp files */
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		t_push();
		path = t_strconcat(ctx->tmpdir, "/", mf->dest, NULL);
		(void)unlink(path);
		t_pop();
	}

	pool_unref(ctx->pool);
}
