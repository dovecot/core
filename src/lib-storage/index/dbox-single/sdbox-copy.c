/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "nfs-workarounds.h"
#include "dbox-save.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "mail-copy.h"

static int
sdbox_copy_hardlink(struct mail_save_context *_ctx, struct mail *mail)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct sdbox_mailbox *dest_mbox =
		(struct sdbox_mailbox *)_ctx->transaction->box;
	struct sdbox_mailbox *src_mbox;
	struct dbox_file *src_file, *dest_file;
	const char *src_path;
	int ret;

	if (strcmp(mail->box->storage->name, SDBOX_STORAGE_NAME) == 0)
		src_mbox = (struct sdbox_mailbox *)mail->box;
	else {
		/* Source storage isn't sdbox, can't hard link */
		return 0;
	}

	src_file = sdbox_file_init(src_mbox, mail->uid);
	dest_file = sdbox_file_init(dest_mbox, 0);

	src_path = src_file->primary_path;
	ret = nfs_safe_link(src_path, dest_file->cur_path, FALSE);
	if (ret < 0 && errno == ENOENT && src_file->alt_path != NULL) {
		src_path = src_file->alt_path;
		ret = nfs_safe_link(src_path, dest_file->cur_path, FALSE);
	}
	if (ret < 0) {
		if (ECANTLINK(errno))
			return 0;

		if (errno == ENOENT)
			mail_set_expunged(mail);
		else {
			mail_storage_set_critical(
				_ctx->transaction->box->storage,
				"link(%s, %s) failed: %m",
				src_path, dest_file->cur_path);
		}
		return -1;
	}

	dbox_save_add_to_index(ctx);
	sdbox_save_add_file(_ctx, dest_file);
	if (_ctx->dest_mail != NULL)
		mail_set_seq(_ctx->dest_mail, ctx->seq);
	return 1;
}

static bool
sdbox_compatible_file_modes(struct mailbox *box1, struct mailbox *box2)
{
	return box1->file_create_mode == box2->file_create_mode &&
		box1->file_create_gid == box2->file_create_gid;
}

int sdbox_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)_t->box;
	int ret;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	ctx->finished = TRUE;
	if (sdbox_compatible_file_modes(&mbox->box, mail->box)) {
		T_BEGIN {
			ret = sdbox_copy_hardlink(_ctx, mail);
		} T_END;

		if (ret != 0) {
			index_save_context_free(_ctx);
			return ret > 0 ? 0 : -1;
		}

		/* non-fatal hardlinking failure, try the slow way */
	}
	return mail_storage_copy(_ctx, mail);
}
