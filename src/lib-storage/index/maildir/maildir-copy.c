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

struct hardlink_ctx {
	const char *dest_path;
	bool success;
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

	ctx->success = TRUE;
	return 1;
}

static int
maildir_copy_hardlink(struct maildir_transaction_context *t, struct mail *mail,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      struct mail *dest_mail)
{
	struct maildir_mailbox *dest_mbox =
		(struct maildir_mailbox *)t->ictx.ibox;
	struct maildir_mailbox *src_mbox =
		(struct maildir_mailbox *)mail->box;
	struct maildir_save_context *ctx;
	struct hardlink_ctx do_ctx;
	const char *dest_fname;
	uint32_t seq;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL)
		t->save_ctx = maildir_save_transaction_init(t);
	ctx = t->save_ctx;

	/* don't allow caller to specify recent flag */
	flags &= ~MAIL_RECENT;
	if (dest_mbox->ibox.keep_recent)
		flags |= MAIL_RECENT;

	memset(&do_ctx, 0, sizeof(do_ctx));

	/* the generated filename is _always_ unique, so we don't bother
	   trying to check if it already exists */
	dest_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	if (keywords == NULL || keywords->count == 0) {
		/* no keywords, hardlink directly to destination */
		if (flags == MAIL_RECENT) {
			do_ctx.dest_path =
				t_strconcat(dest_mbox->path, "/new/",
					    dest_fname, NULL);
		} else {
			const char *fname;

			fname = maildir_filename_set_flags(NULL, dest_fname,
							   flags, NULL);

			do_ctx.dest_path =
				t_strconcat(dest_mbox->path, "/cur/",
					    fname, NULL);
		}
	} else {
		/* keywords, hardlink to tmp/ with basename and later when we
		   have uidlist locked, move it to new/cur. */
		do_ctx.dest_path =
			t_strconcat(dest_mbox->path, "/tmp/", dest_fname, NULL);
	}
	if (maildir_file_do(src_mbox, mail->uid, do_hardlink, &do_ctx) < 0)
		return -1;

	if (!do_ctx.success) {
		/* couldn't copy with hardlinking, fallback to copying */
		return 0;
	}

	if (keywords == NULL || keywords->count == 0) {
		/* hardlinked to destination, set hardlinked-flag */
		seq = maildir_save_add(t, dest_fname,
				       flags | MAILDIR_SAVE_FLAG_HARDLINK, NULL,
				       dest_mail != NULL);
	} else {
		/* hardlinked to tmp/, treat as normal copied mail */
		seq = maildir_save_add(t, dest_fname, flags, keywords,
				       dest_mail != NULL);
	}

	if (dest_mail != NULL) {
		i_assert(seq != 0);

		if (mail_set_seq(dest_mail, seq) < 0)
			return -1;
	}
	return 1;
}

int maildir_copy(struct mailbox_transaction_context *_t, struct mail *mail,
		 enum mail_flags flags, struct mail_keywords *keywords,
		 struct mail *dest_mail)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;
	int ret;

	if (mbox->storage->copy_with_hardlinks &&
	    mail->box->storage == mbox->ibox.box.storage) {
		t_push();
		ret = maildir_copy_hardlink(t, mail, flags,
					    keywords, dest_mail);
		t_pop();

		if (ret > 0)
			return 0;
		if (ret < 0)
			return -1;

		/* non-fatal hardlinking failure, try the slow way */
	}

	return mail_storage_copy(_t, mail, flags, keywords, dest_mail);
}
