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

struct rollback {
	struct rollback *next;
	const char *fname;
};

static int maildir_hardlink_file(struct mail_index *index,
				 struct mail_index_record *rec,
				 const char **fname, const char *new_path)
{
	const char *path;

	*fname = maildir_get_location(index, rec);
	if (*fname == NULL)
		return -1;

	if ((rec->index_flags & INDEX_MAIL_FLAG_MAILDIR_NEW) != 0) {
		/* probably in new/ dir */
		path = t_strconcat(index->mailbox_path, "/new/", *fname, NULL);
		if (link(path, new_path) == 0)
			return 1;

		if (ENOSPACE(errno)) {
			index->nodiskspace = TRUE;
			return -1;
		}
		if (errno == EACCES || errno == EXDEV)
			return -1;
		if (errno != ENOENT) {
			index_set_error(index, "link(%s, %s) failed: %m",
					path, new_path);
			return -1;
		}
	}

	path = t_strconcat(index->mailbox_path, "/cur/", *fname, NULL);
	if (link(path, new_path) == 0)
		return 1;

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		return -1;
	}
	if (errno == EACCES || errno == EXDEV)
		return -1;
	if (errno != ENOENT) {
		index_set_error(index, "link(%s, %s) failed: %m",
				path, new_path);
		return -1;
	}

	return 0;
}

static int maildir_copy_hardlink(struct mail *mail,
				 struct maildir_copy_context *ctx)
{
	struct index_mail *imail = (struct index_mail *) mail;
        struct rollback *rb;
	const char *fname, *dest_fname, *dest_path;
	enum mail_flags flags;
	int i, ret, found;

	flags = mail->get_flags(mail)->flags;

	/* link the file */
	dest_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	dest_fname = maildir_filename_set_flags(dest_fname, flags);
	dest_path = t_strconcat(ctx->ibox->index->mailbox_path, "/new/",
				dest_fname, NULL);

	for (i = 0;; i++) {
		ret = maildir_hardlink_file(imail->ibox->index, imail->data.rec,
					    &fname, dest_path);
		if (ret != 0)
			break;

		if (i == 10) {
			mail_storage_set_error(mail->box->storage,
				"File name keeps changing, copy failed");
			break;
		}

		if (!maildir_index_sync_readonly(imail->ibox->index, fname,
						 &found)) {
			ret = -1;
			break;
		}

		if (!found)
			break;
	}

	if (ret > 0) {
		if (ctx->pool == NULL) {
			ctx->pool = pool_alloconly_create("hard copy rollbacks",
							  2048);
		}

		rb = p_new(ctx->pool, struct rollback, 1);
		rb->fname = p_strdup(ctx->pool, dest_fname);
		rb->next = ctx->rollbacks;
		ctx->rollbacks = rb;
	}

	return ret;
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
