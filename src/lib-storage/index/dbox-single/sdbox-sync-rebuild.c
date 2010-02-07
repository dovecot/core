/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dbox-sync-rebuild.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"

#include <stdlib.h>
#include <dirent.h>

static void sdbox_sync_set_uidvalidity(struct dbox_sync_rebuild_context *ctx)
{
	struct mailbox *box = &ctx->ibox->box;
	uint32_t uid_validity;

	/* if uidvalidity is set in the old index, use it */
	uid_validity = mail_index_get_header(ctx->view)->uid_validity;
	if (uid_validity == 0)
		uid_validity = dbox_get_uidvalidity_next(box->list);

	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
}

static int sdbox_sync_add_file_index(struct dbox_sync_rebuild_context *ctx,
				     struct dbox_file *file, uint32_t uid)
{
	uint32_t seq;
	uoff_t size;
	bool deleted;
	int ret;

	if ((ret = dbox_file_open(file, &deleted)) > 0) {
		if (deleted)
			return 0;
		ret = dbox_file_get_mail_stream(file, 0, &size, NULL);
	}

	if (ret <= 0) {
		if (ret < 0)
			return -1;

		i_warning("dbox: Ignoring broken file: %s", file->cur_path);
		return 0;
	}

	mail_index_append(ctx->trans, uid, &seq);
	T_BEGIN {
		dbox_sync_rebuild_index_metadata(ctx, seq, uid);
	} T_END;
	return 0;
}

static int
sdbox_sync_add_file(struct dbox_sync_rebuild_context *ctx,
		    const char *fname, bool primary)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)ctx->ibox;
	struct dbox_file *file;
	unsigned long uid;
	char *p;
	int ret;

	if (strncmp(fname, SDBOX_MAIL_FILE_PREFIX,
		    strlen(SDBOX_MAIL_FILE_PREFIX)) != 0)
		return 0;
	fname += strlen(SDBOX_MAIL_FILE_PREFIX);

	uid = strtoul(fname, &p, 10);
	if (*p != '\0' || uid == 0 || uid >= (uint32_t)-1) {
		i_warning("dbox %s: Ignoring invalid filename %s",
			  ctx->ibox->box.path, fname);
		return 0;
	}

	file = sdbox_file_init(mbox, uid);
	if (!primary)
		file->cur_path = file->alt_path;
	ret = sdbox_sync_add_file_index(ctx, file, uid);
	dbox_file_unref(&file);
	return ret;
}

static int sdbox_sync_index_rebuild_dir(struct dbox_sync_rebuild_context *ctx,
					const char *path, bool primary)
{
	struct mail_storage *storage = ctx->ibox->box.storage;
	DIR *dir;
	struct dirent *d;
	int ret = 0;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			if (!primary) {
				/* alt directory doesn't exist, ignore */
				return 0;
			}
			mailbox_set_deleted(&ctx->ibox->box);
			return -1;
		}
		mail_storage_set_critical(storage,
			"opendir(%s) failed: %m", path);
		return -1;
	}
	do {
		errno = 0;
		if ((d = readdir(dir)) == NULL)
			break;

		ret = sdbox_sync_add_file(ctx, d->d_name, primary);
	} while (ret >= 0);
	if (errno != 0) {
		mail_storage_set_critical(storage,
			"readdir(%s) failed: %m", path);
		ret = -1;
	}

	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", path);
		ret = -1;
	}
	return ret;
}

static void sdbox_sync_update_header(struct dbox_sync_rebuild_context *ctx)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)ctx->ibox;
	struct sdbox_index_header hdr;

	if (sdbox_read_header(mbox, &hdr) < 0)
		memset(&hdr, 0, sizeof(hdr));
	if (!mail_guid_128_is_empty(hdr.mailbox_guid))
		mail_generate_guid_128(hdr.mailbox_guid);
	mail_index_update_header_ext(ctx->trans, mbox->hdr_ext_id, 0,
				     &hdr, sizeof(hdr));
}

static int
sdbox_sync_index_rebuild_singles(struct dbox_sync_rebuild_context *ctx)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)ctx->ibox;
	int ret = 0;

	sdbox_sync_set_uidvalidity(ctx);
	if (sdbox_sync_index_rebuild_dir(ctx, ctx->ibox->box.path, TRUE) < 0)
		ret = -1;
	else if (mbox->alt_path != NULL)
		ret = sdbox_sync_index_rebuild_dir(ctx, mbox->alt_path, FALSE);
	sdbox_sync_update_header(ctx);
	return ret;
}

int sdbox_sync_index_rebuild(struct sdbox_mailbox *mbox)
{
	struct dbox_sync_rebuild_context *ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	int ret;

	view = mail_index_view_open(mbox->ibox.box.index);
	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	ctx = dbox_sync_index_rebuild_init(&mbox->ibox, view, trans);
	ret = sdbox_sync_index_rebuild_singles(ctx);
	dbox_sync_index_rebuild_deinit(&ctx);

	if (ret < 0)
		mail_index_transaction_rollback(&trans);
	else
		ret = mail_index_transaction_commit(&trans);
	mail_index_view_close(&view);

	if (ret == 0)
		mbox->sync_rebuild = FALSE;
	return ret;
}
