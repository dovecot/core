/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mail-index-alloc-cache.h"
#include "mailbox-log.h"
#include "mailbox-list-private.h"
#include "mail-copy.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "mdbox-map.h"
#include "mdbox-file.h"
#include "mdbox-sync.h"
#include "mdbox-storage-rebuild.h"
#include "mdbox-storage.h"

extern struct mail_storage mdbox_deleted_storage;
extern struct mailbox mdbox_deleted_mailbox;
extern struct dbox_storage_vfuncs mdbox_deleted_dbox_storage_vfuncs;

static struct mail_storage *mdbox_deleted_storage_alloc(void)
{
	struct mdbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("mdbox deleted storage", 2048);
	storage = p_new(pool, struct mdbox_storage, 1);
	storage->storage.v = mdbox_dbox_storage_vfuncs;
	storage->storage.storage = mdbox_deleted_storage;
	storage->storage.storage.pool = pool;
	return &storage->storage.storage;
}

static struct mailbox *
mdbox_deleted_mailbox_alloc(struct mail_storage *storage,
			    struct mailbox_list *list,
			    const char *vname, enum mailbox_flags flags)
{
	struct mdbox_mailbox *mbox;
	pool_t pool;

	flags |= MAILBOX_FLAG_READONLY | MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("mdbox deleted mailbox", 1024*3);
	mbox = p_new(pool, struct mdbox_mailbox, 1);
	mbox->box = mdbox_deleted_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &mdbox_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = (struct mdbox_storage *)storage;
	return &mbox->box;
}

static int
mdbox_deleted_mailbox_create_indexes(struct mailbox *box,
				     const struct mailbox_update *update,
				     struct mail_index_transaction *trans)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	struct mail_index_transaction *new_trans = NULL;
	uint32_t uid_validity = ioloop_time;
	uint32_t uid_next = 1;

	if (update != NULL && update->uid_validity != 0)
		uid_validity = update->uid_validity;

	if (trans == NULL) {
		new_trans = mail_index_transaction_begin(box->view, 0);
		trans = new_trans;
	}

	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, next_uid),
		&uid_next, sizeof(uid_next), TRUE);
	mbox->creating = TRUE;
	mdbox_update_header(mbox, trans, update);
	mbox->creating = FALSE;

	if (new_trans != NULL) {
		if (mail_index_transaction_commit(&new_trans) < 0) {
			mailbox_set_index_error(box);
			return -1;
		}
	}
	return 0;
}

static const char *
mdbox_get_attachment_path_suffix(struct dbox_file *file ATTR_UNUSED)
{
	return "";
}

static int
mdbox_deleted_mailbox_get_metadata(struct mailbox *box,
				   enum mailbox_metadata_items items,
				   struct mailbox_metadata *metadata_r)
{
	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;

	if ((items & MAILBOX_METADATA_GUID) != 0)
		guid_128_generate(metadata_r->guid);
	return 0;
}

static struct mail_save_context *
mdbox_deleted_save_alloc(struct mailbox_transaction_context *t)
{
	struct mail_save_context *ctx;

	ctx = i_new(struct mail_save_context, 1);
	ctx->transaction = t;
	return ctx;
}

static int
mdbox_deleted_save_begin(struct mail_save_context *ctx,
			 struct istream *input ATTR_UNUSED)
{
	mail_storage_set_error(ctx->transaction->box->storage,
		MAIL_ERROR_NOTPOSSIBLE, "mdbox_deleted doesn't support saving mails");
	return -1;
}

static int
mdbox_deleted_save_continue(struct mail_save_context *ctx ATTR_UNUSED)
{
	return -1;
}

static int mdbox_deleted_save_finish(struct mail_save_context *ctx)
{
	index_save_context_free(ctx);
	return -1;
}

static void
mdbox_deleted_save_cancel(struct mail_save_context *ctx)
{
	index_save_context_free(ctx);
}

static int mdbox_deleted_sync(struct mdbox_mailbox *mbox,
			      enum mdbox_sync_flags flags ATTR_UNUSED)
{
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	struct mdbox_mail_index_record rec;
	struct mdbox_map_mail_index_record map_rec;
	enum mail_index_sync_flags sync_flags;
	uint16_t refcount;
	uint32_t map_seq, map_count, seq, uid = 0;
	int ret = 0;

	if (mbox->mdbox_deleted_synced) {
		/* don't bother supporting incremental syncs */
		return 0;
	}
	if (!mbox->box.inbox_user && mbox->box.name[0] != '\0') {
		/* since mailbox list currently shows all the existing
		   mailboxes, we don't want all of them to list the deleted
		   messages. only show messages in user's INBOX or the
		   namespace prefix. */
		return 0;
	}

	if (mdbox_map_open(mbox->storage->map) < 0)
		return -1;

	if (mdbox_deleted_mailbox_create_indexes(&mbox->box, NULL, NULL) < 0)
		return -1;

	i_zero(&rec);
	rec.save_date = ioloop_time;

	sync_flags = index_storage_get_sync_flags(&mbox->box);
	if (mail_index_sync_begin(mbox->box.index, &index_sync_ctx,
				  &sync_view, &trans, sync_flags) < 0) {
		mailbox_set_index_error(&mbox->box);
		return -1;
	}

	map_count = mdbox_map_get_messages_count(mbox->storage->map);
	for (map_seq = 1; map_seq <= map_count; map_seq++) {
		if (mdbox_map_lookup_seq_full(mbox->storage->map, map_seq,
					      &map_rec, &refcount) < 0) {
			ret = -1;
			break;
		}
		if (refcount == 0) {
			rec.map_uid = mdbox_map_lookup_uid(mbox->storage->map,
							   map_seq);
			mail_index_append(trans, ++uid, &seq);
			mail_index_update_ext(trans, seq,
					      mbox->ext_id, &rec, NULL);
		}
	}

	if (ret < 0)
		mail_index_sync_rollback(&index_sync_ctx);
	else {
		if (mail_index_sync_commit(&index_sync_ctx) < 0) {
			mailbox_set_index_error(&mbox->box);
			ret = -1;
		} else {
			mbox->mdbox_deleted_synced = TRUE;
		}
	}
	return ret;
}

static struct mailbox_sync_context *
mdbox_deleted_storage_sync_init(struct mailbox *box,
				enum mailbox_sync_flags flags)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	enum mdbox_sync_flags mdbox_sync_flags = 0;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	if (ret == 0 && (index_mailbox_want_full_sync(&mbox->box, flags) ||
			 mbox->storage->corrupted))
		ret = mdbox_deleted_sync(mbox, mdbox_sync_flags);

	return index_mailbox_sync_init(box, flags, ret < 0);
}

struct mail_storage mdbox_deleted_storage = {
	.name = MDBOX_DELETED_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA,

	.v = {
                mdbox_get_setting_parser_info,
		mdbox_deleted_storage_alloc,
		mdbox_storage_create,
		mdbox_storage_destroy,
		NULL,
		dbox_storage_get_list_settings,
		NULL,
		mdbox_deleted_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox mdbox_deleted_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		mdbox_mailbox_open,
		index_storage_mailbox_close,
		index_storage_mailbox_free,
		dbox_mailbox_create,
		index_storage_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		mdbox_deleted_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		index_storage_list_index_has_changed,
		index_storage_list_index_update_sync,
		mdbox_deleted_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		dbox_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		dbox_mail_alloc,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		mdbox_deleted_save_alloc,
		mdbox_deleted_save_begin,
		mdbox_deleted_save_continue,
		mdbox_deleted_save_finish,
		mdbox_deleted_save_cancel,
		mail_storage_copy,
		NULL,
		NULL,
		NULL,
		index_storage_is_inconsistent
	}
};

struct dbox_storage_vfuncs mdbox_deleted_dbox_storage_vfuncs = {
	mdbox_file_unrefed,
	mdbox_file_create_fd,
	mdbox_mail_open,
	mdbox_deleted_mailbox_create_indexes,
	mdbox_get_attachment_path_suffix,
	mdbox_set_mailbox_corrupted,
	mdbox_set_file_corrupted
};
