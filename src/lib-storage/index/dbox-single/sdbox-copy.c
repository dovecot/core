/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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
	struct fs_file *src_fsfile, *dest_fsfile;
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
		   dest_storage->attachment_dir) != 0 ||
	    strcmp(src_storage->storage.set->mail_attachment_fs,
		   dest_storage->storage.set->mail_attachment_fs) != 0 ||
	    strcmp(src_storage->storage.set->mail_attachment_hash,
		   dest_storage->storage.set->mail_attachment_hash) != 0) {
		/* different attachment dirs/settings between storages.
		   have to copy the slow way. */
		return 0;
	}

	if ((ret = sdbox_file_get_attachments(&src_file->file,
					      &extrefs_line)) <= 0)
		return ret < 0 ? -1 : 1;

	pool = pool_alloconly_create("sdbox attachments copy", 1024);
	p_array_init(&extrefs, pool, 16);
	if (!index_attachment_parse_extrefs(extrefs_line, pool, &extrefs)) {
		mailbox_set_critical(&dest_file->mbox->box,
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
					   guid_generate(), NULL);
		dest = t_strdup_printf("%s/%s", dest_storage->attachment_dir,
				       dest_relpath);
		/* we verified above that attachment_fs is compatible for
		   src and dest, so it doesn't matter which storage's
		   attachment_fs we use. in any case we need to use the same
		   one or fs_copy() will crash with assert. */
		src_fsfile = fs_file_init(dest_storage->attachment_fs, src,
					  FS_OPEN_MODE_READONLY);
		dest_fsfile = fs_file_init(dest_storage->attachment_fs, dest,
					   FS_OPEN_MODE_READONLY);
		if (fs_copy(src_fsfile, dest_fsfile) < 0) {
			mailbox_set_critical(&dest_file->mbox->box, "%s",
				fs_file_last_error(dest_fsfile));
			ret = -1;
		} else {
			array_push_back(&dest_file->attachment_paths,
					&dest_relpath);
		}
		fs_file_deinit(&src_fsfile);
		fs_file_deinit(&dest_fsfile);
	} T_END;
	pool_unref(&pool);
	return ret;
}

static int
sdbox_copy_hardlink(struct mail_save_context *_ctx, struct mail *mail)
{
	struct dbox_save_context *ctx = DBOX_SAVECTX(_ctx);
	struct sdbox_mailbox *dest_mbox = SDBOX_MAILBOX(_ctx->transaction->box);
	struct sdbox_mailbox *src_mbox;
	struct dbox_file *src_file, *dest_file;
	const char *src_path, *dest_path;
	int ret;

	if (strcmp(mail->box->storage->name, SDBOX_STORAGE_NAME) == 0)
		src_mbox = SDBOX_MAILBOX(mail->box);
	else {
		/* Source storage isn't sdbox, can't hard link */
		return 0;
	}

	src_file = sdbox_file_init(src_mbox, mail->uid);
	dest_file = sdbox_file_init(dest_mbox, 0);

	ctx->ctx.data.flags &= ~DBOX_INDEX_FLAG_ALT;

	src_path = src_file->primary_path;
	dest_path = dest_file->primary_path;
	ret = nfs_safe_link(src_path, dest_path, FALSE);
	if (ret < 0 && errno == ENOENT && src_file->alt_path != NULL) {
		src_path = src_file->alt_path;
		if (dest_file->alt_path != NULL) {
			dest_path = dest_file->cur_path = dest_file->alt_path;
			ctx->ctx.data.flags |= DBOX_INDEX_FLAG_ALT;
		}
		ret = nfs_safe_link(src_path, dest_path, FALSE);
	}
	if (ret < 0) {
		if (ECANTLINK(errno))
			ret = 0;
		else if (errno == ENOENT) {
			/* try if the fallback copying code can still
			   read the file (the mail could still have the
			   stream open) */
			ret = 0;
		} else {
			mail_set_critical(mail, "link(%s, %s) failed: %m",
					  src_path, dest_path);
		}
		dbox_file_unref(&src_file);
		dbox_file_unref(&dest_file);
		return ret;
	}

	ret = sdbox_file_copy_attachments((struct sdbox_file *)src_file,
					  (struct sdbox_file *)dest_file);
	if (ret <= 0) {
		(void)sdbox_file_unlink_aborted_save((struct sdbox_file *)dest_file);
		dbox_file_unref(&src_file);
		dbox_file_unref(&dest_file);
		return ret;
	}
	((struct sdbox_file *)dest_file)->written_to_disk = TRUE;

	dbox_save_add_to_index(ctx);
	index_copy_cache_fields(_ctx, mail, ctx->seq);

	sdbox_save_add_file(_ctx, dest_file);
	mail_set_seq_saving(_ctx->dest_mail, ctx->seq);
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
	    _ctx->data.guid == NULL) {
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
