/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "nfs-workarounds.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-filename.h"
#include "maildir-keywords.h"
#include "maildir-sync.h"
#include "index-mail.h"
#include "mail-copy.h"

#include <unistd.h>
#include <sys/stat.h>

struct hardlink_ctx {
	const char *dest_path;
	bool success:1;
};

static int do_hardlink(struct maildir_mailbox *mbox, const char *path,
		       struct hardlink_ctx *ctx)
{
	int ret;

	if (mbox->storage->storage.set->mail_nfs_storage)
		ret = nfs_safe_link(path, ctx->dest_path, FALSE);
	else
		ret = link(path, ctx->dest_path);
	if (ret < 0) {
		if (errno == ENOENT)
			return 0;

		if (ENOQUOTA(errno)) {
			mail_storage_set_error(&mbox->storage->storage,
				MAIL_ERROR_NOQUOTA, MAIL_ERRSTR_NO_QUOTA);
			return -1;
		}

		/* we could handle the EEXIST condition by changing the
		   filename, but it practically never happens so just fallback
		   to standard copying for the rare cases when it does. */
		if (errno == EACCES || ECANTLINK(errno) || errno == EEXIST)
			return 1;

		mailbox_set_critical(&mbox->box, "link(%s, %s) failed: %m",
				     path, ctx->dest_path);
		return -1;
	}

	ctx->success = TRUE;
	return 1;
}

static int
maildir_copy_hardlink(struct mail_save_context *ctx, struct mail *mail)
{
	struct maildir_mailbox *dest_mbox = MAILDIR_MAILBOX(ctx->transaction->box);
	struct maildir_mailbox *src_mbox;
	struct maildir_filename *mf;
	struct hardlink_ctx do_ctx;
	const char *path, *guid, *dest_fname;
	uoff_t vsize, size;
	enum mail_lookup_abort old_abort;

	if (strcmp(mail->box->storage->name, MAILDIR_STORAGE_NAME) == 0)
		src_mbox = MAILDIR_MAILBOX(mail->box);
	else if (strcmp(mail->box->storage->name, "raw") == 0) {
		/* lda uses raw format */
		src_mbox = NULL;
	} else {
		/* Can't hard link files from the source storage */
		return 0;
	}

	/* hard link to tmp/ with a newly generated filename and later when we
	   have uidlist locked, move it to new/cur. */
	dest_fname = maildir_filename_generate();
	i_zero(&do_ctx);
	do_ctx.dest_path =
		t_strdup_printf("%s/tmp/%s", mailbox_get_path(&dest_mbox->box),
				dest_fname);
	if (src_mbox != NULL) {
		/* maildir */
		if (maildir_file_do(src_mbox, mail->uid,
				    do_hardlink, &do_ctx) < 0)
			return -1;
	} else {
		/* raw / lda */
		if (mail_get_special(mail, MAIL_FETCH_STORAGE_ID,
				     &path) < 0 || *path == '\0')
			return 0;
		if (do_hardlink(dest_mbox, path, &do_ctx) < 0)
			return -1;
	}

	if (!do_ctx.success) {
		/* couldn't copy with hardlinking, fallback to copying */
		return 0;
	}

	/* hardlinked to tmp/, treat as normal copied mail */
	mf = maildir_save_add(ctx, dest_fname, mail);
	if (mail_get_special(mail, MAIL_FETCH_GUID, &guid) == 0) {
		if (*guid != '\0')
			maildir_save_set_dest_basename(ctx, mf, guid);
	}

	/* finish copying keywords */
	maildir_save_finish_keywords(ctx);

	/* remember size/vsize if possible */
	old_abort = mail->lookup_abort;
	mail->lookup_abort = MAIL_LOOKUP_ABORT_READ_MAIL;
	if (mail_get_physical_size(mail, &size) < 0)
		size = (uoff_t)-1;
	if (mail_get_virtual_size(mail, &vsize) < 0)
		vsize = (uoff_t)-1;
	maildir_save_set_sizes(mf, size, vsize);
	mail->lookup_abort = old_abort;
	return 1;
}

int maildir_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox_transaction_context *_t = ctx->transaction;
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(_t->box);
	int ret;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (mbox->storage->set->maildir_copy_with_hardlinks &&
	    mail_storage_copy_can_use_hardlink(mail->box, &mbox->box)) {
		T_BEGIN {
			ret = maildir_copy_hardlink(ctx, mail);
		} T_END;

		if (ret != 0) {
			index_save_context_free(ctx);
			return ret > 0 ? 0 : -1;
		}

		/* non-fatal hardlinking failure, try the slow way */
	}

	return mail_storage_copy(ctx, mail);
}
