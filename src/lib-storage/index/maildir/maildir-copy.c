/* Copyright (C) 2002-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "index-mail.h"
#include "mail-copy.h"

#include <stdlib.h>
#include <unistd.h>

struct maildir_copy_context {
	struct maildir_mailbox *mbox;
	int hardlink;

        struct maildir_uidlist_sync_ctx *uidlist_sync_ctx;
	struct maildir_keywords_sync_ctx *keywords_sync_ctx;

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
			mail_storage_set_error(STORAGE(mbox->storage),
					       "Not enough disk space");
			return -1;
		}
		if (errno == EACCES || errno == EXDEV)
			return 1;

		mail_storage_set_critical(STORAGE(mbox->storage),
					  "link(%s, %s) failed: %m",
					  path, ctx->dest_path);
		return -1;
	}

	ctx->found = TRUE;
	return 1;
}

static int
maildir_copy_hardlink(struct mail *mail,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      struct maildir_copy_context *ctx)
{
	struct index_mail *imail = (struct index_mail *)mail;
	struct maildir_mailbox *dest_mbox = ctx->mbox;
	struct maildir_mailbox *src_mbox =
		(struct maildir_mailbox *)imail->ibox;
	struct hardlink_ctx do_ctx;
	struct rollback *rb;
	const char *dest_fname;
	unsigned int keywords_count;
	array_t ARRAY_DEFINE(keywords_arr, unsigned int);

	dest_fname = maildir_generate_tmp_filename(&ioloop_timeval);

	keywords_count = keywords == NULL ? 0 : keywords->count;
	if (keywords_count > 0) {
		ARRAY_CREATE(&keywords_arr, pool_datastack_create(),
			     unsigned int, keywords->count);
		array_append(&keywords_arr, keywords->idx, keywords->count);

		if (ctx->keywords_sync_ctx == NULL) {
			/* uidlist must be locked while accessing
			   keywords files */
			if (maildir_uidlist_sync_init(dest_mbox->uidlist, TRUE,
						&ctx->uidlist_sync_ctx) <= 0) {
				/* error or timeout */
				return -1;
			}

			ctx->keywords_sync_ctx =
				maildir_keywords_sync_init(dest_mbox->keywords,
							dest_mbox->ibox.index);
		}
	}

	flags &= ~MAIL_RECENT;
	if (dest_mbox->ibox.keep_recent)
		flags |= MAIL_RECENT;

	dest_fname = maildir_filename_set_flags(ctx->keywords_sync_ctx,
						dest_fname, flags,
						keywords_count != 0 ?
						&keywords_arr : NULL);

	if (keywords_count == 0 && flags == MAIL_RECENT)
		dest_fname = t_strconcat("new/", dest_fname, NULL);
	else
		dest_fname = t_strconcat("cur/", dest_fname, NULL);

	memset(&do_ctx, 0, sizeof(do_ctx));
	do_ctx.dest_path =
		t_strconcat(dest_mbox->path, "/", dest_fname, NULL);

	if (maildir_file_do(src_mbox, imail->mail.mail.uid,
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
	if (ctx->keywords_sync_ctx != NULL) {
		maildir_keywords_sync_deinit(ctx->keywords_sync_ctx);
		maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
	}
	pool_unref(ctx->pool);
	return 0;
}

void maildir_transaction_copy_rollback(struct maildir_copy_context *ctx)
{
        struct rollback *rb;

	for (rb = ctx->rollbacks; rb != NULL; rb = rb->next) {
		t_push();
		(void)unlink(t_strconcat(ctx->mbox->path, "/",
					 rb->fname, NULL));
		t_pop();
	}

	pool_unref(ctx->pool);
}

int maildir_copy(struct mailbox_transaction_context *_t, struct mail *mail,
		 enum mail_flags flags, struct mail_keywords *keywords,
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
	    mail->box->storage == STORAGE(ctx->mbox->storage)) {
		// FIXME: handle dest_mail
		t_push();
		ret = maildir_copy_hardlink(mail, flags, keywords, ctx);
		t_pop();

		if (ret > 0)
			return 0;
		if (ret < 0)
			return -1;

		/* non-fatal hardlinking failure, try the slow way */
	}

	return mail_storage_copy(_t, mail, flags, keywords, dest_mail);
}
