/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

struct mail_filename {
	struct mail_filename *next;
	const char *src, *dest;
};

struct mail_save_context {
	pool_t pool;

	struct index_mailbox *ibox;
	int transaction;

	const char *tmpdir, *newdir;
	struct mail_filename *files;
};

static const char *
maildir_read_into_tmp(struct index_mailbox *ibox, const char *dir,
		      struct istream *input)
{
	const char *path, *fname;
	struct ostream *output;
	int fd;

	fd = maildir_create_tmp(ibox->index, dir, &path);
	if (fd == -1)
		return NULL;

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	fname++;

	t_push();
	output = o_stream_create_file(fd, data_stack_pool, 4096,
				      IO_PRIORITY_DEFAULT, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	if (!index_storage_save(ibox->box.storage, path, input, output,
				NULL, NULL))
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
	t_pop();
	return fname;
}

static int maildir_copy(struct mail_save_context *ctx,
			const char *src, const char *dest)
{
	const char *tmp_path, *new_path;
	int failed;

	t_push();

	tmp_path = t_strconcat(ctx->tmpdir, "/", src, NULL);
	new_path = t_strconcat(ctx->newdir, "/", dest, NULL);

	if (link(tmp_path, new_path) == 0)
		failed = FALSE;
	else {
		failed = TRUE;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(ctx->ibox->box.storage,
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(ctx->ibox->box.storage,
						  "link(%s, %s) failed: %m",
						  tmp_path, new_path);
		}
	}

	(void)unlink(tmp_path);
	t_pop();
	return !failed;
}

int maildir_storage_save_next(struct mail_save_context *ctx,
			      const struct mail_full_flags *flags,
			      time_t received_date,
			      int timezone_offset __attr_unused__,
			      struct istream *data)
{
	enum mail_flags mail_flags;
        struct utimbuf buf;
	const char *fname, *dest_fname, *tmp_path;
	int failed;

	mail_flags = flags->flags;
	if (!index_mailbox_fix_custom_flags(ctx->ibox, &mail_flags,
					    flags->custom_flags,
					    flags->custom_flags_count))
		return FALSE;

	t_push();

	/* create the file into tmp/ directory */
	fname = maildir_read_into_tmp(ctx->ibox, ctx->tmpdir, data);
	if (fname == NULL) {
		t_pop();
		return FALSE;
	}

	tmp_path = t_strconcat(ctx->tmpdir, "/", fname, NULL);

	/* set the received_date by modifying mtime */
	buf.actime = ioloop_time;
	buf.modtime = received_date;
	if (utime(tmp_path, &buf) < 0) {
		mail_storage_set_critical(ctx->ibox->box.storage,
					  "utime() failed for %s: %m",
					  tmp_path);
		t_pop();
		return FALSE;
	}

	/* now, if we want to be able to rollback the whole append session,
	   we'll just store the name of this temp file and move it later
	   into new/ */
	dest_fname = mail_flags == 0 ? fname :
		maildir_filename_set_flags(fname, mail_flags);
	if (ctx->transaction) {
		struct mail_filename *mf;

		mf = p_new(ctx->pool, struct mail_filename, 1);
		mf->next = ctx->files;
		mf->src = p_strdup(ctx->pool, fname);
		mf->dest = p_strdup(ctx->pool, dest_fname);
		ctx->files = mf;

		failed = FALSE;
	} else {
		failed = !maildir_copy(ctx, fname, dest_fname);
	}

	t_pop();
	return !failed;
}

struct mail_save_context *
maildir_storage_save_init(struct mailbox *box, int transaction)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_save_context *ctx;
	pool_t pool;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return NULL;
	}

	pool = pool_alloconly_create("mail_save_context", 4096);
	ctx = p_new(pool, struct mail_save_context, 1);
	ctx->pool = pool;
	ctx->ibox = ibox;
	ctx->transaction = transaction;

	ctx->tmpdir = p_strconcat(pool, ibox->index->mailbox_path,
				  "/tmp", NULL);
	ctx->newdir = p_strconcat(pool, ibox->index->mailbox_path,
				  "/new", NULL);

	return ctx;
}

int maildir_storage_save_deinit(struct mail_save_context *ctx, int rollback)
{
	struct mail_filename *mf, *mf2;
	const char *path;
	int failed = FALSE;

	if (rollback) {
		/* clean up the temp files */
		for (mf = ctx->files; mf != NULL; mf = mf->next) {
			t_push();
			path = t_strconcat(ctx->tmpdir, "/", mf->dest, NULL);
			(void)unlink(path);
			t_pop();
		}
	} else {
		/* move them into new/ */
		for (mf = ctx->files; mf != NULL; mf = mf->next) {
			if (!maildir_copy(ctx, mf->src, mf->dest)) {
				failed = TRUE;
				break;
			}
		}

		if (failed) {
			/* failed, try to unlink the mails already moved */
			for (mf2 = ctx->files; mf2 != mf; mf2 = mf2->next) {
				t_push();
				path = t_strconcat(ctx->newdir, "/",
						   mf2->dest, NULL);
				(void)unlink(path);
				t_pop();
			}
		}
	}

	pool_unref(ctx->pool);
	return !failed;
}
