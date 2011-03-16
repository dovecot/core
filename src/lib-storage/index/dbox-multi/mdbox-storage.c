/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mail-index-alloc-cache.h"
#include "mailbox-log.h"
#include "mailbox-list-private.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "mdbox-map.h"
#include "mdbox-file.h"
#include "mdbox-sync.h"
#include "mdbox-storage-rebuild.h"
#include "mdbox-storage.h"

extern struct mail_storage mdbox_storage;
extern struct mailbox mdbox_mailbox;
extern struct dbox_storage_vfuncs mdbox_dbox_storage_vfuncs;

static struct mail_storage *mdbox_storage_alloc(void)
{
	struct mdbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("mdbox storage", 2048);
	storage = p_new(pool, struct mdbox_storage, 1);
	storage->storage.v = mdbox_dbox_storage_vfuncs;
	storage->storage.storage = mdbox_storage;
	storage->storage.storage.pool = pool;
	return &storage->storage.storage;
}

static int
mdbox_storage_create(struct mail_storage *_storage, struct mail_namespace *ns,
		     const char **error_r)
{
	struct mdbox_storage *storage = (struct mdbox_storage *)_storage;
	const char *dir;

	storage->set = mail_storage_get_driver_settings(_storage);
	storage->preallocate_space = storage->set->mdbox_preallocate_space;

	if (*ns->list->set.mailbox_dir_name == '\0') {
		*error_r = "mdbox: MAILBOXDIR must not be empty";
		return -1;
	}

	_storage->unique_root_dir =
		p_strdup(_storage->pool, ns->list->set.root_dir);

	dir = mailbox_list_get_path(ns->list, NULL, MAILBOX_LIST_PATH_TYPE_DIR);
	storage->storage_dir = p_strconcat(_storage->pool, dir,
					   "/"MDBOX_GLOBAL_DIR_NAME, NULL);
	storage->alt_storage_dir = p_strconcat(_storage->pool,
					       ns->list->set.alt_dir,
					       "/"MDBOX_GLOBAL_DIR_NAME, NULL);
	i_array_init(&storage->open_files, 64);

	storage->map = mdbox_map_init(storage, ns->list);
	return dbox_storage_create(_storage, ns, error_r);
}

static void mdbox_storage_destroy(struct mail_storage *_storage)
{
	struct mdbox_storage *storage = (struct mdbox_storage *)_storage;

	mdbox_files_free(storage);
	mdbox_map_deinit(&storage->map);
	if (storage->to_close_unused_files != NULL)
		timeout_remove(&storage->to_close_unused_files);

	if (array_is_created(&storage->move_from_alt_map_uids))
		array_free(&storage->move_from_alt_map_uids);
	if (array_is_created(&storage->move_to_alt_map_uids))
		array_free(&storage->move_to_alt_map_uids);
	array_free(&storage->open_files);
	dbox_storage_destroy(_storage);
}

struct mailbox *
mdbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *name, enum mailbox_flags flags)
{
	struct mdbox_mailbox *mbox;
	struct index_mailbox_context *ibox;
	pool_t pool;

	/* dbox can't work without index files */
	flags &= ~MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("mdbox mailbox", 1024*3);
	mbox = p_new(pool, struct mdbox_mailbox, 1);
	mbox->box = mdbox_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &mdbox_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, name, flags, DBOX_INDEX_PREFIX);
	mail_index_set_fsync_mode(mbox->box.index,
				  storage->set->parsed_fsync_mode,
				  MAIL_INDEX_SYNC_TYPE_APPEND |
				  MAIL_INDEX_SYNC_TYPE_EXPUNGE);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->save_commit_pre = mdbox_transaction_save_commit_pre;
	ibox->save_commit_post = mdbox_transaction_save_commit_post;
	ibox->save_rollback = mdbox_transaction_save_rollback;
	ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS |
		MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;

	mbox->storage = (struct mdbox_storage *)storage;
	mbox->ext_id =
		mail_index_ext_register(mbox->box.index, "mdbox", 0,
					sizeof(struct mdbox_mail_index_record),
					sizeof(uint32_t));
	mbox->hdr_ext_id =
		mail_index_ext_register(mbox->box.index, "mdbox-hdr",
					sizeof(struct mdbox_index_header), 0, 0);
	mbox->guid_ext_id =
		mail_index_ext_register(mbox->box.index, "guid",
					0, MAIL_GUID_128_SIZE, 1);
	return &mbox->box;
}

static void mdbox_mailbox_close(struct mailbox *box)
{
	struct mdbox_storage *mstorage = (struct mdbox_storage *)box->storage;

	if (mstorage->corrupted && !mstorage->rebuilding_storage)
		(void)mdbox_storage_rebuild(mstorage);

	index_storage_mailbox_close(box);
}

int mdbox_read_header(struct mdbox_mailbox *mbox,
		      struct mdbox_index_header *hdr)
{
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(mbox->box.view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < MDBOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->creating || data_size != 0)) {
		mail_storage_set_critical(&mbox->storage->storage.storage,
			"mdbox %s: Invalid dbox header size: %"PRIuSIZE_T,
			mbox->box.path, data_size);
		mdbox_storage_set_corrupted(mbox->storage);
		return -1;
	}
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr, data, I_MIN(data_size, sizeof(*hdr)));
	return 0;
}

void mdbox_update_header(struct mdbox_mailbox *mbox,
			 struct mail_index_transaction *trans,
			 const struct mailbox_update *update)
{
	struct mdbox_index_header hdr, new_hdr;

	if (mdbox_read_header(mbox, &hdr) < 0)
		memset(&hdr, 0, sizeof(hdr));

	new_hdr = hdr;

	if (update != NULL && !mail_guid_128_is_empty(update->mailbox_guid)) {
		memcpy(new_hdr.mailbox_guid, update->mailbox_guid,
		       sizeof(new_hdr.mailbox_guid));
	} else if (mail_guid_128_is_empty(new_hdr.mailbox_guid)) {
		mail_generate_guid_128(new_hdr.mailbox_guid);
	}

	new_hdr.map_uid_validity =
		mdbox_map_get_uid_validity(mbox->storage->map);
	if (memcmp(&hdr, &new_hdr, sizeof(hdr)) != 0) {
		mail_index_update_header_ext(trans, mbox->hdr_ext_id, 0,
					     &new_hdr, sizeof(new_hdr));
	}
}

static int mdbox_write_index_header(struct mailbox *box,
				    const struct mailbox_update *update,
				    struct mail_index_transaction *trans)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	struct mail_index_transaction *new_trans = NULL;
	const struct mail_index_header *hdr;
	uint32_t uid_validity, uid_next;

	if (mdbox_map_open_or_create(mbox->storage->map) < 0)
		return -1;

	if (trans == NULL) {
		new_trans = mail_index_transaction_begin(box->view, 0);
		trans = new_trans;
	}

	hdr = mail_index_get_header(box->view);
	uid_validity = hdr->uid_validity;
	if (update != NULL && update->uid_validity != 0)
		uid_validity = update->uid_validity;
	else if (uid_validity == 0) {
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

	mdbox_update_header(mbox, trans, update);
	if (new_trans != NULL) {
		if (mail_index_transaction_commit(&new_trans) < 0) {
			mail_storage_set_index_error(box);
			return -1;
		}
	}
	return 0;
}

static int mdbox_mailbox_create_indexes(struct mailbox *box,
					const struct mailbox_update *update,
					struct mail_index_transaction *trans)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	int ret;

	mbox->creating = TRUE;
	ret = mdbox_write_index_header(box, update, trans);
	mbox->creating = FALSE;
	return ret;
}

void mdbox_storage_set_corrupted(struct mdbox_storage *storage)
{
	if (storage->corrupted) {
		/* already set it corrupted (possibly recursing back here) */
		return;
	}

	storage->corrupted = TRUE;
	storage->corrupted_rebuild_count = (uint32_t)-1;

	if (mdbox_map_open(storage->map) > 0 &&
	    mdbox_map_refresh(storage->map) == 0) {
		storage->corrupted_rebuild_count =
			mdbox_map_get_rebuild_count(storage->map);
	}
}

static const char *
mdbox_get_attachment_path_suffix(struct dbox_file *file ATTR_UNUSED)
{
	return "";
}

static void mdbox_set_mailbox_corrupted(struct mailbox *box)
{
	struct mdbox_storage *mstorage = (struct mdbox_storage *)box->storage;

	mdbox_storage_set_corrupted(mstorage);
}

static void mdbox_set_file_corrupted(struct dbox_file *file)
{
	struct mdbox_storage *mstorage = (struct mdbox_storage *)file->storage;

	mdbox_storage_set_corrupted(mstorage);
}

static int
mdbox_mailbox_get_guid(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE])
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	struct mdbox_index_header hdr;

	if (mdbox_read_header(mbox, &hdr) < 0)
		memset(&hdr, 0, sizeof(hdr));

	if (mail_guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (mdbox_write_index_header(box, NULL, NULL) < 0 ||
		    mdbox_read_header(mbox, &hdr) < 0)
			return -1;
	}
	memcpy(guid, hdr.mailbox_guid, MAIL_GUID_128_SIZE);
	return 0;
}

static int
mdbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (update->cache_fields != NULL)
		index_storage_mailbox_update_cache_fields(box, update);
	return mdbox_write_index_header(box, update, NULL);
}

static int mdbox_mailbox_unref_mails(struct mdbox_mailbox *mbox)
{
	struct mdbox_map_atomic_context *atomic;
	struct mdbox_map_transaction_context *map_trans;
	const struct mail_index_header *hdr;
	uint32_t seq, map_uid;
	int ret = 0;

	atomic = mdbox_map_atomic_begin(mbox->storage->map);
	map_trans = mdbox_map_transaction_begin(atomic, FALSE);
	hdr = mail_index_get_header(mbox->box.view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		if (mdbox_mail_lookup(mbox, mbox->box.view, seq,
				      &map_uid) < 0) {
			ret = -1;
			break;
		}

		if (mdbox_map_update_refcount(map_trans, map_uid, -1) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret == 0)
		ret = mdbox_map_transaction_commit(map_trans);
	mdbox_map_transaction_free(&map_trans);
	if (mdbox_map_atomic_finish(&atomic) < 0)
		ret = -1;
	return ret;
}

static int mdbox_mailbox_delete(struct mailbox *box)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;

	if (box->opened) {
		if (mdbox_mailbox_unref_mails(mbox) < 0)
			return -1;
	}
	return index_storage_mailbox_delete(box);
}

struct mail_storage mdbox_storage = {
	.name = MDBOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT,

	.v = {
                mdbox_get_setting_parser_info,
		mdbox_storage_alloc,
		mdbox_storage_create,
		mdbox_storage_destroy,
		NULL,
		dbox_storage_get_list_settings,
		NULL,
		mdbox_mailbox_alloc,
		mdbox_purge
	}
};

struct mailbox mdbox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		dbox_mailbox_open,
		mdbox_mailbox_close,
		index_storage_mailbox_free,
		dbox_mailbox_create,
		mdbox_mailbox_update,
		mdbox_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		mdbox_mailbox_get_guid,
		NULL,
		NULL,
		mdbox_storage_sync_init,
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
		mdbox_save_alloc,
		mdbox_save_begin,
		dbox_save_continue,
		mdbox_save_finish,
		mdbox_save_cancel,
		mdbox_copy,
		NULL,
		index_storage_is_inconsistent
	}
};

struct dbox_storage_vfuncs mdbox_dbox_storage_vfuncs = {
	mdbox_file_unrefed,
	mdbox_file_create_fd,
	mdbox_mail_open,
	mdbox_mailbox_create_indexes,
	mdbox_get_attachment_path_suffix,
	mdbox_set_mailbox_corrupted,
	mdbox_set_file_corrupted
};
