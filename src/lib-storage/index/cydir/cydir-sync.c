/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "cydir-storage.h"
#include "cydir-sync.h"

static int cydir_sync_set_uidvalidity(struct cydir_sync_context *ctx)
{
	struct mail_index_transaction *trans;
	uint32_t uid_validity = ioloop_time;
	uint32_t seq;
	uoff_t offset;

	trans = mail_index_transaction_begin(ctx->sync_view, FALSE, TRUE);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);

	if (mail_index_transaction_commit(&trans, &seq, &offset) < 0) {
		mail_storage_set_index_error(&ctx->mbox->ibox);
		return -1;
	}
	return 0;
}

static string_t *cydir_get_path_prefix(struct cydir_mailbox *mbox)
{
	string_t *path = t_str_new(256);
	const char *dir;

	dir = mailbox_list_get_path(STORAGE(mbox->storage)->list,
				    mbox->ibox.box.name,
				    MAILBOX_LIST_PATH_TYPE_MAILBOX);
	str_append(path, dir);
	str_append_c(path, '/');
	return path;
}

static int cydir_sync_index(struct cydir_sync_context *ctx)
{
	const struct mail_index_header *hdr;
	struct mail_index_sync_rec sync_rec;
	string_t *path = NULL;
	unsigned int prefix_len = 0;
	uint32_t seq1, seq2, uid;
	int ret;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity == 0) {
		if (cydir_sync_set_uidvalidity(ctx) < 0)
			return -1;
	}

	/* unlink expunged messages */
	while ((ret = mail_index_sync_next(ctx->index_sync_ctx,
					   &sync_rec)) > 0) {
		if (sync_rec.type != MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			continue;

		if (mail_index_lookup_uid_range(ctx->sync_view,
						sync_rec.uid1, sync_rec.uid2,
						&seq1, &seq2) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			return -1;
		}
		if (seq1 == 0) {
			/* already expunged everything. nothing to do. */
			continue;
		}

		if (path == NULL) {
			path = cydir_get_path_prefix(ctx->mbox);
			prefix_len = str_len(path);
		}

		for (; seq1 <= seq2; seq1++) {
			if (mail_index_lookup_uid(ctx->sync_view, seq1,
						  &uid) < 0) {
				mail_storage_set_index_error(&ctx->mbox->ibox);
				return -1;
			}

			str_truncate(path, prefix_len);
			str_printfa(path, "%u.", uid);
			if (unlink(str_c(path)) < 0 && errno != ENOENT) {
				mail_storage_set_critical(
					STORAGE(ctx->mbox->storage),
					"unlink(%s) failed: %m", str_c(path));
				/* continue anyway */
			}
		}
	}
	return 0;
}

int cydir_sync_begin(struct cydir_mailbox *mbox,
		     struct cydir_sync_context **ctx_r)
{
	struct cydir_sync_context *ctx;
	int ret;

	ctx = i_new(struct cydir_sync_context, 1);
	ctx->mbox = mbox;
	ret = mail_index_sync_begin(mbox->ibox.index, &ctx->index_sync_ctx,
				    &ctx->sync_view, (uint32_t)-1, (uoff_t)-1,
				    !mbox->ibox.keep_recent, TRUE);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->ibox);
		i_free(ctx);
		return ret;
	}

	if (cydir_sync_index(ctx) < 0) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		i_free(ctx);
		return -1;
	}

	*ctx_r = ctx;
	return 0;
}

int cydir_sync_finish(struct cydir_sync_context **_ctx, bool success)
{
	struct cydir_sync_context *ctx = *_ctx;
	int ret = success ? 0 : -1;

	*_ctx = NULL;
	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}
	i_free(ctx);
	return 0;
}

int cydir_sync(struct cydir_mailbox *mbox)
{
	struct cydir_sync_context *sync_ctx;

	if (cydir_sync_begin(mbox, &sync_ctx) < 0)
		return -1;

	return cydir_sync_finish(&sync_ctx, TRUE);
}

struct mailbox_sync_context *
cydir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct cydir_mailbox *mbox = (struct cydir_mailbox *)box;
	int ret = 0;

	if (!box->opened)
		index_storage_mailbox_open(&mbox->ibox);

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    mbox->ibox.sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <=
	    ioloop_time)
		ret = cydir_sync(mbox);

	return index_mailbox_sync_init(box, flags, ret < 0);
}
