/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mail-search-build.h"
#include "mailbox-list-private.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"
#include "sdbox-storage.h"

extern struct mail_storage dbox_storage, sdbox_storage;
extern struct mailbox sdbox_mailbox;
extern struct dbox_storage_vfuncs sdbox_dbox_storage_vfuncs;

static struct mail_storage *sdbox_storage_alloc(void)
{
	struct sdbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("sdbox storage", 512+256);
	storage = p_new(pool, struct sdbox_storage, 1);
	storage->storage.v = sdbox_dbox_storage_vfuncs;
	storage->storage.storage = sdbox_storage;
	storage->storage.storage.pool = pool;
	return &storage->storage.storage;
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

	pool = pool_alloconly_create("sdbox mailbox", 1024*3);
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
	struct mail_index_view *view;
	const void *data;
	size_t data_size;
	int ret;

	view = mail_index_view_open(mbox->box.index);
	mail_index_get_header_ext(view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < SDBOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->box.creating || data_size != 0)) {
		if (log_error) {
			mail_storage_set_critical(
				&mbox->storage->storage.storage,
				"sdbox %s: Invalid dbox header size",
				mbox->box.path);
		}
		ret = -1;
	} else {
		memset(hdr, 0, sizeof(*hdr));
		memcpy(hdr, data, I_MIN(data_size, sizeof(*hdr)));
		ret = 0;
	}
	mail_index_view_close(&view);
	return ret;
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
	memcpy(mbox->mailbox_guid, new_hdr.mailbox_guid,
	       sizeof(mbox->mailbox_guid));
}

static int sdbox_mailbox_create_indexes(struct mailbox *box,
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
	if (update != NULL && update->min_first_recent_uid != 0 &&
	    hdr->first_recent_uid < update->min_first_recent_uid) {
		uint32_t first_recent_uid = update->min_first_recent_uid;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	if (update != NULL && update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(box->view) <
	    					update->min_highest_modseq) {
		mail_index_modseq_enable(box->index);
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

static const char *
sdbox_get_attachment_path_suffix(struct dbox_file *_file)
{
	struct sdbox_file *file = (struct sdbox_file *)_file;

	return t_strdup_printf("-%s-%u",
			mail_guid_128_to_string(file->mbox->mailbox_guid),
			file->uid);
}

void sdbox_set_mailbox_corrupted(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	struct sdbox_index_header hdr;

	if (sdbox_read_header(mbox, &hdr, TRUE) < 0 || hdr.rebuild_count == 0)
		mbox->corrupted_rebuild_count = 1;
	else
		mbox->corrupted_rebuild_count = hdr.rebuild_count;
}

static void sdbox_set_file_corrupted(struct dbox_file *_file)
{
	struct sdbox_file *file = (struct sdbox_file *)_file;

	sdbox_set_mailbox_corrupted(&file->mbox->box);
}

static int sdbox_mailbox_open(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	struct sdbox_index_header hdr;

	if (dbox_mailbox_open(box) < 0)
		return -1;

	if (box->creating) {
		/* wait for mailbox creation to initialize the index */
		return 0;
	}

	/* get/generate mailbox guid */
	if (sdbox_read_header(mbox, &hdr, FALSE) < 0) {
		/* it's possible that this mailbox is just now being created
		   by another process. lock it first and see if the header is
		   available then. */
		struct mail_index_sync_ctx *sync_ctx;
		struct mail_index_view *view;
		struct mail_index_transaction *trans;

		if (mail_index_sync_begin(box->index, &sync_ctx,
					  &view, &trans, 0) > 0)
			(void)mail_index_sync_commit(&sync_ctx);

		if (sdbox_read_header(mbox, &hdr, TRUE) < 0)
			memset(&hdr, 0, sizeof(hdr));
	}

	if (mail_guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (sdbox_mailbox_create_indexes(box, NULL, NULL) < 0 ||
		    sdbox_read_header(mbox, &hdr, TRUE) < 0)
			return -1;
	}
	memcpy(mbox->mailbox_guid, hdr.mailbox_guid,
	       sizeof(mbox->mailbox_guid));
	return 0;
}

static void sdbox_mailbox_close(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;

	if (mbox->corrupted_rebuild_count != 0)
		(void)sdbox_sync(mbox, 0);
	index_storage_mailbox_close(box);
}

static int sdbox_mailbox_delete(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;
	struct mail_search_context *ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
	struct mail_search_args *search_args;
	struct dbox_file *file;
	struct sdbox_file *sfile;

	if (!box->opened || mbox->storage->storage.attachment_dir == NULL)
		return index_storage_mailbox_delete(box);

	/* mark the mailbox deleted to avoid race conditions */
	if (mailbox_mark_index_deleted(box, TRUE) < 0)
		return -1;

	/* ulink all dbox mails and their attachements in the mailbox. */
	t = mailbox_transaction_begin(box, 0);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL);
	mail_search_args_unref(&search_args);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(ctx, mail)) {
		file = sdbox_file_init(mbox, mail->uid);
		sfile = (struct sdbox_file *)file;
		(void)sdbox_file_unlink_with_attachments(sfile);
		dbox_file_unref(&file);
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&ctx) < 0) {
		/* maybe we missed some mails. oh well, can't help it. */
	}
	mailbox_transaction_rollback(&t);

	return index_storage_mailbox_delete(box);
}

static int
sdbox_mailbox_get_guid(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE])
{
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)box;

	memcpy(guid, mbox->mailbox_guid, MAIL_GUID_128_SIZE);
	return 0;
}

static int
dbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (update->cache_fields != NULL)
		index_storage_mailbox_update_cache_fields(box, update);
	return sdbox_mailbox_create_indexes(box, update, NULL);
}

struct mail_storage sdbox_storage = {
	.name = SDBOX_STORAGE_NAME,
	.class_flags = 0,

	.v = {
                NULL,
		sdbox_storage_alloc,
		dbox_storage_create,
		dbox_storage_destroy,
		NULL,
		dbox_storage_get_list_settings,
		NULL,
		sdbox_mailbox_alloc,
		NULL
	}
};

struct mail_storage dbox_storage = {
	.name = "dbox", /* alias */
	.class_flags = 0,

	.v = {
                NULL,
		sdbox_storage_alloc,
		dbox_storage_create,
		dbox_storage_destroy,
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
		sdbox_mailbox_open,
		sdbox_mailbox_close,
		index_storage_mailbox_free,
		dbox_mailbox_create,
		dbox_mailbox_update,
		sdbox_mailbox_delete,
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
		NULL,
		index_storage_is_inconsistent
	}
};

struct dbox_storage_vfuncs sdbox_dbox_storage_vfuncs = {
	sdbox_file_free,
	sdbox_file_create_fd,
	sdbox_mail_open,
	sdbox_mailbox_create_indexes,
	sdbox_get_attachment_path_suffix,
	sdbox_set_mailbox_corrupted,
	sdbox_set_file_corrupted
};
