/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "maildir-storage.h"
#include "mail-custom-flags.h"
#include "mail-index-util.h"
#include "index-messageset.h"

#include <stdlib.h>
#include <unistd.h>

struct maildir_copy_context {
	struct index_mailbox *ibox;
	int hardlink;

	pool_t pool;
	struct rollback *rollbacks;

	struct mail_copy_context *ctx;
};

struct hardlink_ctx {
	const char *dest_path;
	int found;
};

struct rollback {
	struct rollback *next;
	const char *fname;
};

static int do_hardlink(struct mail_index *index, const char *path,
		       void *context)
{
	struct hardlink_ctx *ctx = context;

	if (link(path, ctx->dest_path) < 0) {
		if (errno == ENOENT)
			return 0;

		if (ENOSPACE(errno)) {
			index->nodiskspace = TRUE;
			return -1;
		}
		if (errno == EACCES || errno == EXDEV)
			return 1;

		index_set_error(index, "link(%s, %s) failed: %m",
				path, ctx->dest_path);
		return -1;
	}

	ctx->found = TRUE;
	return 1;
}

static int maildir_copy_hardlink(struct mail *mail,
				 struct maildir_copy_context *ctx)
{
	struct index_mail *imail = (struct index_mail *) mail;
	struct hardlink_ctx do_ctx;
	struct rollback *rb;
	const char *dest_fname;

	dest_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	dest_fname = maildir_filename_set_flags(dest_fname,
						mail->get_flags(mail)->flags);

	memset(&do_ctx, 0, sizeof(do_ctx));
	do_ctx.dest_path = t_strconcat(ctx->ibox->index->mailbox_path, "/new/",
				       dest_fname, NULL);

	if (!maildir_file_do(imail->ibox->index, imail->data.rec,
			     do_hardlink, &do_ctx))
		return -1;

	if (!do_ctx.found)
		return 0;

	if (ctx->pool == NULL)
		ctx->pool = pool_alloconly_create("hard copy rollbacks", 2048);

	rb = p_new(ctx->pool, struct rollback, 1);
	rb->fname = p_strdup(ctx->pool, dest_fname);

	rb->next = ctx->rollbacks;
	ctx->rollbacks = rb;
	return 1;
}

struct mail_copy_context *maildir_storage_copy_init(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct maildir_copy_context *ctx;

	if (box->is_readonly(box)) {
		mail_storage_set_error(box->storage,
				       "Destination mailbox is read-only");
		return NULL;
	}

	ctx = i_new(struct maildir_copy_context, 1);
	ctx->hardlink = getenv("MAILDIR_COPY_WITH_HARDLINKS") != NULL;
	ctx->ibox = ibox;
	return (struct mail_copy_context *) ctx;
}

int maildir_storage_copy_deinit(struct mail_copy_context *_ctx, int rollback)
{
	struct maildir_copy_context *ctx = (struct maildir_copy_context *) _ctx;
        struct rollback *rb;
	int ret = TRUE;

	if (ctx->ctx != NULL)
		ret = index_storage_copy_deinit(ctx->ctx, rollback);

	if (rollback) {
		for (rb = ctx->rollbacks; rb != NULL; rb = rb->next) {
			t_push();
			(void)unlink(t_strconcat(ctx->ibox->index->mailbox_path,
						 "/new/", rb->fname, NULL));
			t_pop();
		}
	}

	if (ctx->pool != NULL)
		pool_unref(ctx->pool);

	i_free(ctx);
	return ret;
}

int maildir_storage_copy(struct mail *mail, struct mail_copy_context *_ctx)
{
	struct maildir_copy_context *ctx = (struct maildir_copy_context *) _ctx;
	int ret;

	if (ctx->hardlink && mail->box->storage == ctx->ibox->box.storage) {
		t_push();
		ret = maildir_copy_hardlink(mail, ctx);
		t_pop();

		if (ret > 0)
			return TRUE;
		if (ret < 0)
			return FALSE;

		/* non-fatal hardlinking failure, try the slow way */
	}

	if (ctx->ctx == NULL)
		ctx->ctx = index_storage_copy_init(&ctx->ibox->box);

	return index_storage_copy(mail, ctx->ctx);
}
