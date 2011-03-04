/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "nfs-workarounds.h"
#include "fs-api.h"
#include "dbox-save.h"
#include "dbox-attachment.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "mail-copy.h"

static int
sdbox_file_copy_attachments(struct sdbox_file *src_file,
			    struct sdbox_file *dest_file)
{
	struct dbox_storage *src_storage = src_file->file.storage;
	struct dbox_storage *dest_storage = dest_file->file.storage;
	ARRAY_TYPE(mail_attachment_extref) extrefs;
	const struct mail_attachment_extref *extref;
	const char *extrefs_line, *src, *dest, *dest_relpath;
	pool_t pool;
	int ret;

	if (src_storage->attachment_dir == NULL) {
		/* no attachments in source storage */
		return 1;
	}
	if (dest_storage->attachment_dir == NULL ||
	    strcmp(src_storage->attachment_dir,
		   dest_storage->attachment_dir) != 0) {
		/* different attachment dirs between storages.
		   have to copy the slow way. */
		return 0;
	}

	if ((ret = sdbox_file_get_attachments(&src_file->file,
					      &extrefs_line)) <= 0)
		return ret < 0 ? -1 : 1;

	pool = pool_alloconly_create("sdbox attachments copy", 1024);
	p_array_init(&extrefs, pool, 16);
	if (!dbox_attachment_parse_extref(extrefs_line, pool, &extrefs)) {
		mail_storage_set_critical(&dest_storage->storage,
			"Can't copy %s with corrupted extref metadata: %s",
			src_file->file.cur_path, extrefs_line);
		pool_unref(&pool);
		return -1;
	}

	dest_file->attachment_pool =
		pool_alloconly_create("sdbox attachment copy paths", 512);
	p_array_init(&dest_file->attachment_paths, dest_file->attachment_pool,
		     array_count(&extrefs));

	ret = 1;
	array_foreach(&extrefs, extref) T_BEGIN {
		src = t_strdup_printf("%s/%s", dest_storage->attachment_dir,
			sdbox_file_attachment_relpath(src_file, extref->path));
		dest_relpath = p_strconcat(dest_file->attachment_pool,
					   extref->path, "-",
					   mail_generate_guid_string(), NULL);
		dest = t_strdup_printf("%s/%s", dest_storage->attachment_dir,
				       dest_relpath);
		if (fs_link(dest_storage->attachment_fs, src, dest) < 0) {
			mail_storage_set_critical(&dest_storage->storage, "%s",
				fs_last_error(dest_storage->attachment_fs));
			ret = -1;
		} else {
			array_append(&dest_file->attachment_paths,
				     &dest_relpath, 1);
		}
	} T_END;
	pool_unref(&pool);
	return ret;
}

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
			ret = 0;
		else if (errno == ENOENT)
			mail_set_expunged(mail);
		else {
			mail_storage_set_critical(
				_ctx->transaction->box->storage,
				"link(%s, %s) failed: %m",
				src_path, dest_file->cur_path);
		}
		dbox_file_unref(&src_file);
		dbox_file_unref(&dest_file);
		return ret;
	}

	ret = sdbox_file_copy_attachments((struct sdbox_file *)src_file,
					  (struct sdbox_file *)dest_file);
	if (ret <= 0) {
		sdbox_file_unlink_aborted_save((struct sdbox_file *)dest_file);
		dbox_file_unref(&src_file);
		dbox_file_unref(&dest_file);
		return ret;
	}

	dbox_save_add_to_index(ctx);
	index_copy_cache_fields(_ctx, mail, ctx->seq);

	sdbox_save_add_file(_ctx, dest_file);
	if (_ctx->dest_mail != NULL) {
		mail_set_seq(_ctx->dest_mail, ctx->seq);
		_ctx->dest_mail->saving = TRUE;
	}
	dbox_file_unref(&src_file);
	return 1;
}

int sdbox_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)_t->box;
	int ret;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	ctx->finished = TRUE;
	if (mail_storage_copy_can_use_hardlink(mail->box, &mbox->box) &&
	    _ctx->guid == NULL) {
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
