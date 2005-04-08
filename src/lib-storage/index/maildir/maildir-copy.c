/* Copyright (C) 2002-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-storage.h"
#include "index-mail.h"
#include "mail-copy.h"

#include <stdlib.h>
#include <unistd.h>

struct maildir_copy_context {
	struct maildir_mailbox *mbox;
	int hardlink;

	pool_t pool;
	struct rollback *rollbacks;
};

struct hardlink_ctx {
	const char *dest_path;
	int found;
};

struct rollback {
	struct rollback *next;
	const char *fname;
};

static int do_hardlink(struct maildir_mailbox *mbox, const char *path,
		       void *context)
{
	struct hardlink_ctx *ctx = context;

	if (link(path, ctx->dest_path) < 0) {
		if (errno == ENOENT)
			return 0;

		if (ENOSPACE(errno)) {
			mail_storage_set_error(&mbox->storage->storage,
					       "Not enough disk space");
			return -1;
		}
		if (errno == EACCES || errno == EXDEV)
			return 1;

		mail_storage_set_critical(&mbox->storage->storage,
					  "link(%s, %s) failed: %m",
					  path, ctx->dest_path);
		return -1;
	}

	ctx->found = TRUE;
	return 1;
}

static int maildir_copy_hardlink(struct mail *mail,
				 struct maildir_copy_context *ctx)
{
	struct index_mail *imail = (struct index_mail *)mail;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)imail->ibox;
	struct hardlink_ctx do_ctx;
	struct rollback *rb;
	enum mail_flags flags;
	const char *const *keywords;
	const char *dest_fname;

        flags = mail_get_flags(mail);
        keywords = mail_get_keywords(mail);
	dest_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	dest_fname = maildir_filename_set_flags(dest_fname, flags, keywords);

	memset(&do_ctx, 0, sizeof(do_ctx));
	do_ctx.dest_path =
		t_strconcat(ctx->mbox->path, "/new/", dest_fname, NULL);

	if (maildir_file_do(mbox, imail->mail.mail.uid,
			    do_hardlink, &do_ctx) < 0)
		return -1;

	if (!do_ctx.found)
		return 0;

	rb = p_new(ctx->pool, struct rollback, 1);
	rb->fname = p_strdup(ctx->pool, dest_fname);

	rb->next = ctx->rollbacks;
	ctx->rollbacks = rb;
	return 1;
}

static struct maildir_copy_context *
maildir_copy_init(struct maildir_mailbox *mbox)
{
	struct maildir_copy_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("maildir_copy_context", 2048);

	ctx = p_new(pool, struct maildir_copy_context, 1);
	ctx->pool = pool;
	ctx->hardlink = getenv("MAILDIR_COPY_WITH_HARDLINKS") != NULL;
	ctx->mbox = mbox;
	return ctx;
}

int maildir_transaction_copy_commit(struct maildir_copy_context *ctx)
{
	pool_unref(ctx->pool);
	return 0;
}

void maildir_transaction_copy_rollback(struct maildir_copy_context *ctx)
{
        struct rollback *rb;

	for (rb = ctx->rollbacks; rb != NULL; rb = rb->next) {
		t_push();
		(void)unlink(t_strconcat(ctx->mbox->path,
					 "/new/", rb->fname, NULL));
		t_pop();
	}

	pool_unref(ctx->pool);
}

int maildir_copy(struct mailbox_transaction_context *_t, struct mail *mail,
		 struct mail *dest_mail)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;
	struct maildir_copy_context *ctx;
	int ret;

	if (t->copy_ctx == NULL)
		t->copy_ctx = maildir_copy_init(mbox);
	ctx = t->copy_ctx;

	if (ctx->hardlink &&
	    mail->box->storage == &ctx->mbox->storage->storage) {
		// FIXME: handle dest_mail
		t_push();
		ret = maildir_copy_hardlink(mail, ctx);
		t_pop();

		if (ret > 0)
			return 0;
		if (ret < 0)
			return -1;

		/* non-fatal hardlinking failure, try the slow way */
	}

	return mail_storage_copy(_t, mail, dest_mail);
}
