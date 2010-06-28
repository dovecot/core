/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mailbox-list-private.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"
#include "sdbox-storage.h"

extern struct mail_storage dbox_storage;
extern struct mailbox sdbox_mailbox;
extern struct dbox_storage_vfuncs sdbox_dbox_storage_vfuncs;

static struct mail_storage *sdbox_storage_alloc(void)
{
	struct sdbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("dbox storage", 512+256);
	storage = p_new(pool, struct sdbox_storage, 1);
	storage->storage.v = sdbox_dbox_storage_vfuncs;
	storage->storage.storage = dbox_storage;
	storage->storage.storage.pool = pool;
	return &storage->storage.storage;
}

static int
sdbox_storage_create(struct mail_storage *storage ATTR_UNUSED,
		     struct mail_namespace *ns ATTR_UNUSED,
		     const char **error_r ATTR_UNUSED)
{
#ifndef HAVE_FLOCK
	if (master_service_get_client_limit(master_service) > 1) {
		*error_r = "dbox requires client_limit=1 for service "
			"since your OS doesn't support flock()";
		return -1;
	}
#endif
	return 0;
}

static struct mailbox *
sdbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *name, enum mailbox_flags flags)
{
	struct sdbox_mailbox *mbox;
	struct index_mailbox_context *ibox;
	pool_t pool;

	/* dbox can't work without index files */
	flags &= ~MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("dbox mailbox", 1024*3);
	mbox = p_new(pool, struct sdbox_mailbox, 1);
	mbox->box = sdbox_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &sdbox_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, name, flags, DBOX_INDEX_PREFIX);
	mail_index_set_fsync_mode(mbox->box.index,
				  storage->set->parsed_fsync_mode,
				  MAIL_INDEX_SYNC_TYPE_APPEND |
				  MAIL_INDEX_SYNC_TYPE_EXPUNGE);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->save_commit_pre = sdbox_transaction_save_commit_pre;
	ibox->save_commit_post = sdbox_transaction_save_commit_post;
	ibox->save_rollback = sdbox_transaction_save_rollback;
	ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS |
		MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;

	mbox->storage = (struct sdbox_storage *)storage;
	mbox->hdr_ext_id =
		mail_index_ext_register(mbox->box.index, "dbox-hdr",
					sizeof(struct sdbox_index_header), 0, 0);
	return &mbox->box;
}

int sdbox_read_header(struct sdbox_mailbox *mbox,
		      struct sdbox_index_header *hdr, bool log_error)
{
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(mbox->box.view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < SDBOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->creating || data_size != 0)) {
		if (log_error) {
			mail_storage_set_critical(
				&mbox->storage->storage.storage,
				"dbox %s: Invalid dbox header size",
				mbox->box.path);
		}
		return -1;
	}
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr, data, I_MIN(data_size, sizeof(*hdr)));
	return 0;
}

void sdbox_update_header(struct sdbox_mailbox *mbox,
			 struct mail_index_transaction *trans,
			 const struct mailbox_update *update)
{
	struct sdbox_index_header hdr, new_hdr;

	if (sdbox_read_header(mbox, &hdr, TRUE) < 0)
		memset(&hdr, 0, sizeof(hdr));

	new_hdr = hdr;

	if (update != NULL && !mail_guid_128_is_empty(update->mailbox_guid)) {
		memcpy(new_hdr.mailbox_guid, update->mailbox_guid,
		       sizeof(new_hdr.mailbox_guid));
	} else if (mail_guid_128_is_empty(new_hdr.mailbox_guid)) {
		mail_generate_guid_128(new_hdr.mailbox_guid);
	}

	if (memcmp(&hdr, &new_hdr, sizeof(hdr)) != 0) {
		mail_index_update_header_ext(trans, mbox->hdr_ext_id, 0,
					     &new_hdr, sizeof(new_hdr));
	}
}

static int sdbox_write_index_header(struct mailbox *box,
				    const struct mailbox_update *update,
				    struct mail_index_transaction *trans)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	struct mail_index_transaction *new_trans = NULL;
	const struct mail_index_header *hdr;
	uint32_t uid_validity, uid_next;

	if (trans == NULL) {
		new_trans = mail_index_transaction_begin(box->view, 0);
		trans = new_trans;
	}

	hdr = mail_index_get_header(box->view);
	if (update != NULL && update->uid_validity != 0)
		uid_validity = update->uid_validity;
	else if (hdr->uid_validity != 0)
		uid_validity = hdr->uid_validity;
	else {
		/* set uidvalidity */
		uid_validity = dbox_get_uidvalidity_next(box->list);
	}

	if (hdr->uid_validity != uid_validity) {
		if (hdr->uid_validity != 0) {
			/* UIDVALIDITY change requires index to be reset */
			mail_index_reset(trans);
		}
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	if (update != NULL && hdr->next_uid < update->min_next_uid) {
		uid_next = update->min_next_uid;
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, next_uid),
			&uid_next, sizeof(uid_next), TRUE);
	}
	if (update != NULL && update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(box->view) <
	    					update->min_highest_modseq) {
		mail_index_update_highest_modseq(trans,
						 update->min_highest_modseq);
	}

	sdbox_update_header(mbox, trans, update);
	if (new_trans != NULL) {
		if (mail_index_transaction_commit(&new_trans) < 0) {
			mail_storage_set_internal_error(box->storage);
			mail_index_reset_error(box->index);
			return -1;
		}
	}
	return 0;
}

static int sdbox_mailbox_create_indexes(struct mailbox *box,
					const struct mailbox_update *update,
					struct mail_index_transaction *trans)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	int ret;

	mbox->creating = TRUE;
	ret = sdbox_write_index_header(box, update, trans);
	mbox->creating = FALSE;
	return ret;
}

static void sdbox_set_mailbox_corrupted(struct mailbox *box ATTR_UNUSED)
{
	/* FIXME */
}

static void sdbox_set_file_corrupted(struct dbox_file *_file)
{
	struct sdbox_file *file = (struct sdbox_file *)_file;

	sdbox_set_mailbox_corrupted(&file->mbox->box);
}

static int
sdbox_mailbox_get_guid(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE])
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	struct sdbox_index_header hdr;

	if (sdbox_read_header(mbox, &hdr, TRUE) < 0)
		memset(&hdr, 0, sizeof(hdr));

	if (mail_guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (sdbox_write_index_header(box, NULL, NULL) < 0 ||
		    sdbox_read_header(mbox, &hdr, TRUE) < 0)
			return -1;
	}
	memcpy(guid, hdr.mailbox_guid, MAIL_GUID_128_SIZE);
	return 0;
}

static int
dbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	if (!box->opened) {
		if (index_storage_mailbox_open(box, FALSE) < 0)
			return -1;
	}
	if (update->cache_fields != NULL)
		index_storage_mailbox_update_cache_fields(box, update);
	return sdbox_write_index_header(box, update, NULL);
}

struct mail_storage dbox_storage = {
	.name = SDBOX_STORAGE_NAME,
	.class_flags = 0,

	.v = {
                NULL,
		sdbox_storage_alloc,
		sdbox_storage_create,
		NULL,
		NULL,
		dbox_storage_get_list_settings,
		NULL,
		sdbox_mailbox_alloc,
		NULL
	}
};

struct mailbox sdbox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		dbox_mailbox_open,
		index_storage_mailbox_close,
		index_storage_mailbox_free,
		dbox_mailbox_create,
		dbox_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		sdbox_mailbox_get_guid,
		NULL,
		NULL,
		sdbox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		dbox_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		index_transaction_set_max_modseq,
		index_keywords_create,
		index_keywords_create_from_indexes,
		index_keywords_ref,
		index_keywords_unref,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunges,
		NULL,
		NULL,
		NULL,
		dbox_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		sdbox_save_alloc,
		sdbox_save_begin,
		dbox_save_continue,
		sdbox_save_finish,
		sdbox_save_cancel,
		sdbox_copy,
		index_storage_is_inconsistent
	}
};

struct dbox_storage_vfuncs sdbox_dbox_storage_vfuncs = {
	dbox_file_free,
	sdbox_file_create_fd,
	sdbox_mail_open,
	sdbox_mailbox_create_indexes,
	sdbox_set_mailbox_corrupted,
	sdbox_set_file_corrupted
};
