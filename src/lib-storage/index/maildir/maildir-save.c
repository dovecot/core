/* Copyright (C) 2002-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
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
	struct mail_index_transaction *trans;
	struct index_mail mail;

	const char *tmpdir, *newdir;
	struct maildir_filename *files;
};

static const char *
maildir_read_into_tmp(struct index_mailbox *ibox, const char *dir,
		      struct istream *input)
{
	const char *path, *fname;
	struct ostream *output;
	int fd, crlf;

	fd = maildir_create_tmp(ibox, dir, ibox->mail_create_mode, &path);
	if (fd == -1)
		return NULL;

	fname = strrchr(path, '/');
	i_assert(fname != NULL);
	fname++;

	output = o_stream_create_file(fd, pool_datastack_create(), 4096, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	crlf = getenv("MAIL_SAVE_CRLF") != NULL;
	if (mail_storage_save(ibox->box.storage, path, input, output,
			      crlf, crlf, NULL, NULL) < 0)
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
mailbox_save_init(struct maildir_transaction_context *t)
{
        struct index_mailbox *ibox = t->ictx.ibox;
	struct maildir_save_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("maildir_save_context", 4096);
	ctx = p_new(pool, struct maildir_save_context, 1);
	ctx->pool = pool;
	ctx->ibox = ibox;
	ctx->trans = t->ictx.trans;

	index_mail_init(&t->ictx, &ctx->mail, 0, NULL);

	ctx->tmpdir = p_strconcat(pool, ibox->path, "/tmp", NULL);
	ctx->newdir = p_strconcat(pool, ibox->path, "/new", NULL);
	return ctx;
}

int maildir_save(struct mailbox_transaction_context *_t,
		 const struct mail_full_flags *flags,
		 time_t received_date, int timezone_offset __attr_unused__,
		 const char *from_envelope __attr_unused__,
		 struct istream *data, struct mail **mail_r)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_save_context *ctx;
	struct index_mailbox *ibox = t->ictx.ibox;
	struct maildir_filename *mf;
	enum mail_flags mail_flags;
        struct utimbuf buf;
	const char *fname, *dest_fname, *tmp_path;
	enum mail_flags save_flags;
	keywords_mask_t keywords;
	uint32_t seq;

	if (t->save_ctx == NULL)
		t->save_ctx = mailbox_save_init(t);
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

	/* insert into index */
	save_flags = (flags->flags & ~MAIL_RECENT) |
		(ibox->keep_recent ? MAIL_RECENT : 0);
	memset(keywords, 0, INDEX_KEYWORDS_BYTE_COUNT);
	// FIXME: set keywords

	mail_index_append(t->ictx.trans, 0, &seq);
	mail_index_update_flags(t->ictx.trans, seq, MODIFY_REPLACE,
				save_flags, keywords);
	t_pop();

	if (mail_r != NULL) {
		if (index_mail_next(&ctx->mail, seq) < 0)
			return -1;
		*mail_r = &ctx->mail.mail;
	}

	return 0;
}

static void maildir_save_commit_abort(struct maildir_save_context *ctx,
				      struct maildir_filename *pos)
{
	struct maildir_filename *mf;
	string_t *str;

	t_push();
	str = t_str_new(1024);

	/* try to unlink the mails already moved */
	for (mf = ctx->files; mf != pos; mf = mf->next) {
		str_truncate(str, 0);
		str_printfa(str, "%s/%s", ctx->newdir, mf->dest);
		(void)unlink(str_c(str));
	}
	ctx->files = pos;
	t_pop();

	maildir_save_rollback(ctx);
}

int maildir_save_commit(struct maildir_save_context *ctx)
{
	struct maildir_uidlist_sync_ctx *sync_ctx;
	struct maildir_filename *mf;
	uint32_t first_uid, last_uid;
        enum maildir_uidlist_rec_flag flags;
	int ret = 0;

	ret = maildir_uidlist_lock(ctx->ibox->uidlist);
	if (ret <= 0) {
		/* error or timeout - our transaction is broken */
		maildir_save_commit_abort(ctx, ctx->files);
		return -1;
	}

	first_uid = maildir_uidlist_get_next_uid(ctx->ibox->uidlist);
	mail_index_append_assign_uids(ctx->trans, first_uid, &last_uid);

	flags = MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
		MAILDIR_UIDLIST_REC_FLAG_RECENT;

	/* move them into new/ */
	sync_ctx = maildir_uidlist_sync_init(ctx->ibox->uidlist, TRUE);
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		if (maildir_file_move(ctx, mf->src, mf->dest) < 0 ||
		    maildir_uidlist_sync_next(sync_ctx, mf->dest, flags) < 0) {
			(void)maildir_uidlist_sync_deinit(sync_ctx);
			maildir_save_commit_abort(ctx, mf);
			return -1;
		}
	}

	if (maildir_uidlist_sync_deinit(sync_ctx) < 0) {
		maildir_save_commit_abort(ctx, NULL);
		return -1;
	}

	i_assert(maildir_uidlist_get_next_uid(ctx->ibox->uidlist) == last_uid);

	index_mail_deinit(&ctx->mail);
	pool_unref(ctx->pool);
	return ret;
}

void maildir_save_rollback(struct maildir_save_context *ctx)
{
	struct maildir_filename *mf;
	string_t *str;

	t_push();
	str = t_str_new(1024);

	/* clean up the temp files */
	for (mf = ctx->files; mf != NULL; mf = mf->next) {
		str_truncate(str, 0);
		str_printfa(str, "%s/%s", ctx->tmpdir, mf->dest);
		(void)unlink(str_c(str));
	}
	t_pop();

	index_mail_deinit(&ctx->mail);
	pool_unref(ctx->pool);
}
