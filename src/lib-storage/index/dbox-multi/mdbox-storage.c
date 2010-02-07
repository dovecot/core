/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hex-binary.h"
#include "randgen.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "unlink-old-files.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "mail-index-modseq.h"
#include "mailbox-uidvalidity.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "mdbox-map.h"
#include "mdbox-file.h"
#include "mdbox-sync.h"
#include "mdbox-storage-rebuild.h"
#include "mdbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MDBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mdbox_mailbox_list_module)

struct mdbox_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

extern struct mail_storage mdbox_storage;
extern struct mailbox mdbox_mailbox;
extern struct dbox_storage_vfuncs mdbox_dbox_storage_vfuncs;

static MODULE_CONTEXT_DEFINE_INIT(mdbox_mailbox_list_module,
				  &mailbox_list_module_register);

static struct mail_storage *mdbox_storage_alloc(void)
{
	struct mdbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("dbox storage", 512+256);
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
	i_assert(storage->set->mdbox_max_open_files >= 2);

	if (*ns->list->set.mailbox_dir_name == '\0') {
		*error_r = "dbox: MAILBOXDIR must not be empty";
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
	i_array_init(&storage->open_files,
		     I_MIN(storage->set->mdbox_max_open_files, 128));

	storage->map = dbox_map_init(storage, ns->list, storage->storage_dir);
	return 0;
}

static void mdbox_storage_destroy(struct mail_storage *_storage)
{
	struct mdbox_storage *storage = (struct mdbox_storage *)_storage;

	if (storage->storage.files_corrupted) {
		if (mdbox_storage_rebuild(storage) < 0)
			return;
	}

	mdbox_files_free(storage);
	dbox_map_deinit(&storage->map);
	array_free(&storage->open_files);
}

struct mailbox *
mdbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *name, struct istream *input,
		    enum mailbox_flags flags)
{
	struct mdbox_mailbox *mbox;
	pool_t pool;

	/* dbox can't work without index files */
	flags &= ~MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("mdbox mailbox", 1024+512);
	mbox = p_new(pool, struct mdbox_mailbox, 1);
	mbox->ibox.box = mdbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.box.storage = storage;
	mbox->ibox.box.list = list;
	mbox->ibox.box.mail_vfuncs = &mdbox_mail_vfuncs;

	mbox->ibox.save_commit_pre = mdbox_transaction_save_commit_pre;
	mbox->ibox.save_commit_post = mdbox_transaction_save_commit_post;
	mbox->ibox.save_rollback = mdbox_transaction_save_rollback;

	index_storage_mailbox_alloc(&mbox->ibox, name, input, flags,
				    DBOX_INDEX_PREFIX);
	mail_index_set_fsync_types(mbox->ibox.box.index,
				   MAIL_INDEX_SYNC_TYPE_APPEND |
				   MAIL_INDEX_SYNC_TYPE_EXPUNGE);

	mbox->ibox.index_flags |= MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS |
		MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;

	mbox->storage = (struct mdbox_storage *)storage;
	mbox->ext_id =
		mail_index_ext_register(mbox->ibox.box.index, "mdbox", 0,
					sizeof(struct mdbox_mail_index_record),
					sizeof(uint32_t));
	mbox->hdr_ext_id =
		mail_index_ext_register(mbox->ibox.box.index, "mdbox-hdr",
					sizeof(struct mdbox_index_header), 0, 0);
	mbox->guid_ext_id =
		mail_index_ext_register(mbox->ibox.box.index, "guid",
					0, MAIL_GUID_128_SIZE, 1);
	return &mbox->ibox.box;
}

int mdbox_read_header(struct mdbox_mailbox *mbox,
		      struct mdbox_index_header *hdr)
{
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(mbox->ibox.box.view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < MDBOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->creating || data_size != 0)) {
		mail_storage_set_critical(&mbox->storage->storage.storage,
			"dbox %s: Invalid dbox header size",
			mbox->ibox.box.path);
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
		dbox_map_get_uid_validity(mbox->storage->map);
	if (memcmp(&hdr, &new_hdr, sizeof(hdr)) != 0) {
		mail_index_update_header_ext(trans, mbox->hdr_ext_id, 0,
					     &new_hdr, sizeof(new_hdr));
	}
}

static int mdbox_write_index_header(struct mailbox *box,
				    const struct mailbox_update *update)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	struct mail_index_transaction *trans;
	const struct mail_index_header *hdr;
	uint32_t uid_validity, uid_next;

	if (dbox_map_open(mbox->storage->map, TRUE) < 0)
		return -1;

	hdr = mail_index_get_header(box->view);
	trans = mail_index_transaction_begin(box->view, 0);
	mdbox_update_header(mbox, trans, update);

	uid_validity = hdr->uid_validity;
	if (update != NULL && update->uid_validity != 0)
		uid_validity = update->uid_validity;
	else if (uid_validity == 0) {
		/* set uidvalidity */
		uid_validity = dbox_get_uidvalidity_next(box->list);
	}

	if (hdr->uid_validity != uid_validity) {
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

	if (mail_index_transaction_commit(&trans) < 0) {
		mail_storage_set_internal_error(box->storage);
		mail_index_reset_error(box->index);
		return -1;
	}
	return 0;
}

static int mdbox_mailbox_create_indexes(struct mailbox *box,
					const struct mailbox_update *update)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	int ret;

	mbox->creating = TRUE;
	ret = mdbox_write_index_header(box, update);
	mbox->creating = FALSE;
	return ret;
}

static void mdbox_storage_get_status_guid(struct mailbox *box,
					  struct mailbox_status *status_r)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	struct mdbox_index_header hdr;

	if (mdbox_read_header(mbox, &hdr) < 0)
		memset(&hdr, 0, sizeof(hdr));

	if (mail_guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (mdbox_write_index_header(box, NULL) < 0 ||
		    mdbox_read_header(mbox, &hdr) < 0)
			return;
	}
	memcpy(status_r->mailbox_guid, hdr.mailbox_guid,
	       sizeof(status_r->mailbox_guid));
}

static void
mdbox_storage_get_status(struct mailbox *box, enum mailbox_status_items items,
			 struct mailbox_status *status_r)
{
	index_storage_get_status(box, items, status_r);

	if ((items & STATUS_GUID) != 0)
		mdbox_storage_get_status_guid(box, status_r);
}

static int
mdbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	if (!box->opened) {
		if (index_storage_mailbox_open(box) < 0)
			return -1;
	}
	return mdbox_write_index_header(box, update);
}

static int
mdbox_mailbox_unref_mails(struct mailbox_list *list, const char *path)
{
	struct mdbox_storage *storage =
		(struct mdbox_storage *)list->ns->storage;
	const struct mail_storage_settings *old_set;
	struct mail_storage_settings tmp_set;
	struct mailbox *box;
	struct mdbox_mailbox *mbox;
	const struct mail_index_header *hdr;
	const struct mdbox_mail_index_record *dbox_rec;
	struct dbox_map_transaction_context *map_trans;
	ARRAY_TYPE(uint32_t) map_uids;
	const void *data;
	bool expunged;
	uint32_t seq;
	int ret;

	old_set = list->mail_set;
	tmp_set = *list->mail_set;
	tmp_set.mail_full_filesystem_access = TRUE;
	list->mail_set = &tmp_set;
	box = mdbox_mailbox_alloc(&storage->storage.storage, list, path, NULL,
				  MAILBOX_FLAG_IGNORE_ACLS |
				  MAILBOX_FLAG_KEEP_RECENT);
	ret = mailbox_open(box);
	list->mail_set = old_set;
	if (ret < 0) {
		mailbox_close(&box);
		return -1;
	}
	mbox = (struct mdbox_mailbox *)box;

	/* get a list of all map_uids in this mailbox */
	i_array_init(&map_uids, 128);
	hdr = mail_index_get_header(box->view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(box->view, seq, mbox->ext_id,
				      &data, &expunged);
		dbox_rec = data;
		if (dbox_rec == NULL) {
			/* no multi-mails */
			break;
		}
		if (dbox_rec->map_uid != 0)
			array_append(&map_uids, &dbox_rec->map_uid, 1);
	}

	/* unreference the map_uids */
	map_trans = dbox_map_transaction_begin(storage->map, FALSE);
	ret = dbox_map_update_refcounts(map_trans, &map_uids, -1);
	if (ret == 0)
		ret = dbox_map_transaction_commit(map_trans);
	dbox_map_transaction_free(&map_trans);
	array_free(&map_uids);
	mailbox_close(&box);
	return ret;
}

static int
mdbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct mdbox_mailbox_list *mlist = MDBOX_LIST_CONTEXT(list);
	const char *trash_dest;
	int ret;

	/* delete the index and control directories */
	if (mlist->module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	if ((ret = dbox_list_delete_mailbox1(list, name, &trash_dest)) < 0)
		return -1;
	if (ret > 0) {
		if (mdbox_mailbox_unref_mails(list, trash_dest) < 0) {
			/* we've already renamed it. there's no going back. */
			mailbox_list_set_internal_error(list);
			ret = -1;
		}
	}
	return dbox_list_delete_mailbox2(list, name, ret, trash_dest);
}

static int
mdbox_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			  struct mailbox_list *newlist, const char *newname,
			  bool rename_children)
{
	struct mdbox_mailbox_list *oldmlist = MDBOX_LIST_CONTEXT(oldlist);

	if (oldmlist->module_ctx.super.
	    		rename_mailbox(oldlist, oldname, newlist, newname,
				       rename_children) < 0)
		return -1;
	return dbox_list_rename_mailbox(oldlist, oldname, newlist, newname,
					rename_children);
}

static void dbox_storage_add_list(struct mail_storage *storage ATTR_UNUSED,
				  struct mailbox_list *list)
{
	struct mdbox_mailbox_list *mlist;

	mlist = p_new(list->pool, struct mdbox_mailbox_list, 1);
	mlist->module_ctx.super = list->v;

	list->v.iter_is_mailbox = dbox_list_iter_is_mailbox;
	list->v.delete_mailbox = mdbox_list_delete_mailbox;
	list->v.rename_mailbox = mdbox_list_rename_mailbox;
	list->v.rename_mailbox_pre = dbox_list_rename_mailbox_pre;

	MODULE_CONTEXT_SET(list, mdbox_mailbox_list_module, mlist);
}

struct mail_storage mdbox_storage = {
	.name = MDBOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT,

	.v = {
                mdbox_get_setting_parser_info,
		mdbox_storage_alloc,
		mdbox_storage_create,
		mdbox_storage_destroy,
		dbox_storage_add_list,
		dbox_storage_get_list_settings,
		NULL,
		mdbox_mailbox_alloc,
		mdbox_sync_purge
	}
};

struct mailbox mdbox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		dbox_mailbox_open,
		index_storage_mailbox_close,
		dbox_mailbox_create,
		mdbox_mailbox_update,
		mdbox_storage_get_status,
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
		index_storage_is_inconsistent
	}
};

struct dbox_storage_vfuncs mdbox_dbox_storage_vfuncs = {
	mdbox_file_unrefed,
	mdbox_file_create_fd,
	mdbox_mail_open,
	mdbox_mailbox_create_indexes
};
