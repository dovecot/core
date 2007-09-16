/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dbox-storage.h"
#include "dbox-index.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#include <stdlib.h>
#include <dirent.h>

struct dbox_sync_rebuild_context {
	struct dbox_mailbox *mbox;
	struct mail_index_transaction *trans;
};

static int dbox_sync_set_uidvalidity(struct dbox_sync_rebuild_context *ctx)
{
	uint32_t uid_validity;

	if (dbox_index_get_uid_validity(ctx->mbox->dbox_index,
					&uid_validity) < 0)
		return -1;

	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	return 0;
}

static void dbox_sync_index_metadata(struct dbox_sync_rebuild_context *ctx,
				     struct dbox_file *file, uint32_t seq)
{
	const char *value;
	struct mail_keywords *keywords;
	enum mail_flags flags = 0;
	unsigned int i;

	value = dbox_file_metadata_get(file, DBOX_METADATA_FLAGS);
	if (value != NULL) {
		for (i = 0; value[i] != '\0'; i++) {
			if (value[i] != '0' && i < DBOX_METADATA_FLAGS_COUNT)
				flags |= dbox_mail_flags_map[i];
		}
		mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE, flags);
	}

	value = dbox_file_metadata_get(file, DBOX_METADATA_KEYWORDS);
	if (value != NULL) {
		t_push();
		keywords = mail_index_keywords_create(ctx->mbox->ibox.index,
						t_strsplit_spaces(value, " "));
		mail_index_update_keywords(ctx->trans, seq, MODIFY_REPLACE,
					   keywords);
		mail_index_keywords_free(&keywords);
		t_pop();
	}
}

static int dbox_sync_index_file_next(struct dbox_sync_rebuild_context *ctx,
				     struct dbox_file *file, uoff_t *offset)
{
	uint32_t seq, uid;
	uoff_t metadata_offset, physical_size;
	bool expunged;
	int ret;

	ret = dbox_file_seek_next(file, offset, &uid, &physical_size);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		if (uid == 0 && (file->file_id & DBOX_FILE_ID_FLAG_UID) != 0) {
			/* EOF */
			return 0;
		}

		i_warning("%s: Ignoring broken file (header)", file->path);
		return 0;
	}
	if ((file->file_id & DBOX_FILE_ID_FLAG_UID) != 0 &&
	    uid != (file->file_id & ~DBOX_FILE_ID_FLAG_UID)) {
		i_warning("%s: Header contains wrong UID %u", file->path, uid);
		return 0;
	}

	metadata_offset =
		dbox_file_get_metadata_offset(file, *offset, physical_size);
	ret = dbox_file_metadata_seek(file, metadata_offset, &expunged);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		i_warning("%s: Ignoring broken file (metadata)", file->path);
		return 0;
	}
	if (!expunged) {
		mail_index_append(ctx->trans, uid, &seq);
		dbox_sync_index_metadata(ctx, file, seq);
	}
	return 1;
}

static int
dbox_sync_index_uid_file(struct dbox_sync_rebuild_context *ctx,
			 const char *fname)
{
	struct dbox_file *file;
	unsigned long uid;
	char *p;
	uoff_t offset = 0;
	int ret;

	fname += sizeof(DBOX_MAIL_FILE_MULTI_PREFIX)-1;
	uid = strtoul(fname, &p, 10);
	if (*p != '\0' || uid == 0 || uid >= (uint32_t)-1) {
		i_warning("dbox %s: Ignoring invalid filename %s",
			  ctx->mbox->path, fname);
		return 0;
	}

	file = dbox_file_init(ctx->mbox, uid | DBOX_FILE_ID_FLAG_UID);
	ret = dbox_sync_index_file_next(ctx, file, &offset) < 0 ? -1 : 0;
	dbox_file_unref(&file);
	return ret;
}

static int
dbox_sync_index_multi_file(struct dbox_sync_rebuild_context *ctx,
			   const char *fname)
{
	/* FIXME */
	return 0;
}

static int dbox_sync_index_rebuild_ctx(struct dbox_sync_rebuild_context *ctx)
{
	struct mail_storage *storage = ctx->mbox->ibox.box.storage;
	DIR *dir;
	struct dirent *d;
	int ret = 0;

	if (dbox_sync_set_uidvalidity(ctx) < 0)
		return -1;

	dir = opendir(ctx->mbox->path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			ctx->mbox->ibox.mailbox_deleted = TRUE;
			return -1;
		}
		mail_storage_set_critical(storage,
			"opendir(%s) failed: %m", ctx->mbox->path);
		return -1;
	}
	errno = 0;
	for (; ret == 0 && (d = readdir(dir)) != NULL; errno = 0) {
		if (strncmp(d->d_name, DBOX_MAIL_FILE_UID_PREFIX,
			    sizeof(DBOX_MAIL_FILE_UID_PREFIX)-1) == 0)
			ret = dbox_sync_index_uid_file(ctx, d->d_name);
		else if (strncmp(d->d_name, DBOX_MAIL_FILE_MULTI_PREFIX,
				 sizeof(DBOX_MAIL_FILE_MULTI_PREFIX)-1) == 0)
			ret = dbox_sync_index_multi_file(ctx, d->d_name);
	}
	if (errno != 0) {
		mail_storage_set_critical(storage,
			"readdir(%s) failed: %m", ctx->mbox->path);
		ret = -1;
	}

	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", ctx->mbox->path);
		ret = -1;
	}
	return ret;
}

int dbox_sync_index_rebuild(struct dbox_mailbox *mbox)
{
	struct dbox_sync_rebuild_context ctx;
	struct mail_index_view *view;
	uint32_t seq;
	uoff_t offset;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.mbox = mbox;
	view = mail_index_view_open(mbox->ibox.index);
	ctx.trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_reset(ctx.trans);

	if ((ret = dbox_sync_index_rebuild_ctx(&ctx)) < 0)
		mail_index_transaction_rollback(&ctx.trans);
	else
		ret = mail_index_transaction_commit(&ctx.trans, &seq, &offset);
	mail_index_view_close(&view);
	return ret;
}
