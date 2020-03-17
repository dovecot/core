/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mail-index-alloc-cache.h"
#include "mailbox-log.h"
#include "mailbox-list-private.h"
#include "index-pop3-uidl.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "mdbox-map.h"
#include "mdbox-file.h"
#include "mdbox-sync.h"
#include "mdbox-storage-rebuild.h"
#include "mdbox-storage.h"

extern struct mail_storage mdbox_storage;
extern struct mailbox mdbox_mailbox;

static struct event_category event_category_mdbox = {
	.name = "mdbox",
	.parent = &event_category_storage,
};

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

int mdbox_storage_create(struct mail_storage *_storage,
			 struct mail_namespace *ns, const char **error_r)
{
	struct mdbox_storage *storage = MDBOX_STORAGE(_storage);
	const char *dir;

	storage->set = mail_namespace_get_driver_settings(ns, _storage);
	storage->preallocate_space = storage->set->mdbox_preallocate_space;

	if (*ns->list->set.mailbox_dir_name == '\0') {
		*error_r = "mdbox: MAILBOXDIR must not be empty";
		return -1;
	}

	_storage->unique_root_dir =
		p_strdup(_storage->pool, ns->list->set.root_dir);

	dir = mailbox_list_get_root_forced(ns->list, MAILBOX_LIST_PATH_TYPE_DIR);
	storage->storage_dir = p_strconcat(_storage->pool, dir,
					   "/"MDBOX_GLOBAL_DIR_NAME, NULL);
	if (ns->list->set.alt_dir != NULL) {
		storage->alt_storage_dir = p_strconcat(_storage->pool,
							ns->list->set.alt_dir,
							"/"MDBOX_GLOBAL_DIR_NAME, NULL);
	}
	i_array_init(&storage->open_files, 64);

	storage->map = mdbox_map_init(storage, ns->list);
	return dbox_storage_create(_storage, ns, error_r);
}

void mdbox_storage_destroy(struct mail_storage *_storage)
{
	struct mdbox_storage *storage = MDBOX_STORAGE(_storage);

	mdbox_files_free(storage);
	mdbox_map_deinit(&storage->map);
	timeout_remove(&storage->to_close_unused_files);

	if (array_is_created(&storage->move_from_alt_map_uids))
		array_free(&storage->move_from_alt_map_uids);
	if (array_is_created(&storage->move_to_alt_map_uids))
		array_free(&storage->move_to_alt_map_uids);
	array_free(&storage->open_files);
	dbox_storage_destroy(_storage);
}

static const char *
mdbox_storage_find_root_dir(const struct mail_namespace *ns)
{
	bool debug = ns->mail_set->mail_debug;
	const char *home, *path;

	if (ns->owner != NULL &&
	    mail_user_get_home(ns->owner, &home) > 0) {
		path = t_strconcat(home, "/mdbox", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_debug("mdbox: root exists (%s)", path);
			return path;
		} 
		if (debug)
			i_debug("mdbox: access(%s, rwx): failed: %m", path);
	}
	return NULL;
}

static bool mdbox_storage_autodetect(const struct mail_namespace *ns,
				     struct mailbox_list_settings *set)
{
	bool debug = ns->mail_set->mail_debug;
	struct stat st;
	const char *path, *root_dir;

	if (set->root_dir != NULL)
		root_dir = set->root_dir;
	else {
		root_dir = mdbox_storage_find_root_dir(ns);
		if (root_dir == NULL) {
			if (debug)
				i_debug("mdbox: couldn't find root dir");
			return FALSE;
		}
	}

	path = t_strconcat(root_dir, "/"MDBOX_GLOBAL_DIR_NAME, NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_debug("mdbox autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_debug("mdbox autodetect: %s not a directory", path);
		return FALSE;
	}

	set->root_dir = root_dir;
	dbox_storage_get_list_settings(ns, set);
	return TRUE;
}

static struct mailbox *
mdbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
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

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS |
		MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;

	mbox->storage = MDBOX_STORAGE(storage);
	return &mbox->box;
}

int mdbox_mailbox_open(struct mailbox *box)
{
	struct mdbox_mailbox *mbox = MDBOX_MAILBOX(box);
	time_t path_ctime;

	if (dbox_mailbox_check_existence(box, &path_ctime) < 0)
		return -1;
	if (dbox_mailbox_open(box, path_ctime) < 0)
		return -1;

	mbox->ext_id =
		mail_index_ext_register(mbox->box.index, "mdbox", 0,
					sizeof(struct mdbox_mail_index_record),
					sizeof(uint32_t));
	mbox->hdr_ext_id =
		mail_index_ext_register(mbox->box.index, "mdbox-hdr",
					sizeof(struct mdbox_index_header), 0, 0);
	mbox->guid_ext_id =
		mail_index_ext_register(mbox->box.index, "guid",
					0, GUID_128_SIZE, 1);
	return 0;
}

static void mdbox_mailbox_close(struct mailbox *box)
{
	struct mdbox_storage *mstorage = MDBOX_STORAGE(box->storage);

	if (mstorage->corrupted && !mstorage->rebuilding_storage)
		(void)mdbox_storage_rebuild(mstorage);

	index_storage_mailbox_close(box);
}

int mdbox_read_header(struct mdbox_mailbox *mbox,
		      struct mdbox_index_header *hdr, bool *need_resize_r)
{
	const void *data;
	size_t data_size;

	i_assert(mbox->box.opened);

	mail_index_get_header_ext(mbox->box.view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < MDBOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->creating || data_size != 0)) {
		mailbox_set_critical(&mbox->box,
			"mdbox: Invalid dbox header size: %zu",
			data_size);
		mdbox_storage_set_corrupted(mbox->storage);
		return -1;
	}
	i_zero(hdr);
	if (data_size > 0)
		memcpy(hdr, data, I_MIN(data_size, sizeof(*hdr)));
	*need_resize_r = data_size < sizeof(*hdr);
	return 0;
}

void mdbox_update_header(struct mdbox_mailbox *mbox,
			 struct mail_index_transaction *trans,
			 const struct mailbox_update *update)
{
	struct mdbox_index_header hdr, new_hdr;
	bool need_resize;

	if (mdbox_read_header(mbox, &hdr, &need_resize) < 0) {
		i_zero(&hdr);
		need_resize = TRUE;
	}

	new_hdr = hdr;

	if (update != NULL && !guid_128_is_empty(update->mailbox_guid)) {
		memcpy(new_hdr.mailbox_guid, update->mailbox_guid,
		       sizeof(new_hdr.mailbox_guid));
	} else if (guid_128_is_empty(new_hdr.mailbox_guid)) {
		guid_128_generate(new_hdr.mailbox_guid);
	}

	new_hdr.map_uid_validity =
		mdbox_map_get_uid_validity(mbox->storage->map);
	if (need_resize) {
		mail_index_ext_resize_hdr(trans, mbox->hdr_ext_id,
					  sizeof(new_hdr));
	}
	if (memcmp(&hdr, &new_hdr, sizeof(hdr)) != 0) {
		mail_index_update_header_ext(trans, mbox->hdr_ext_id, 0,
					     &new_hdr, sizeof(new_hdr));
	}
}

static int ATTR_NULL(2, 3)
mdbox_write_index_header(struct mailbox *box,
			 const struct mailbox_update *update,
			 struct mail_index_transaction *trans)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)box;
	struct mail_index_transaction *new_trans = NULL;
	struct mail_index_view *view;
	const struct mail_index_header *hdr;
	uint32_t uid_validity, uid_next;

	if (mdbox_map_open_or_create(mbox->storage->map) < 0)
		return -1;

	if (trans == NULL) {
		new_trans = mail_index_transaction_begin(box->view, 0);
		trans = new_trans;
	}

	view = mail_index_view_open(box->index);
	hdr = mail_index_get_header(view);
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
	if (update != NULL && update->min_first_recent_uid != 0 &&
	    hdr->first_recent_uid < update->min_first_recent_uid) {
		uint32_t first_recent_uid = update->min_first_recent_uid;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	if (update != NULL && update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(view) < update->min_highest_modseq) {
		mail_index_modseq_enable(box->index);
		mail_index_update_highest_modseq(trans,
						 update->min_highest_modseq);
	}
	mail_index_view_close(&view);

	if (box->inbox_user && box->creating) {
		/* initialize pop3-uidl header when creating mailbox
		   (not on mailbox_update()) */
		index_pop3_uidl_set_max_uid(box, trans, 0);
	}

	mdbox_update_header(mbox, trans, update);
	if (new_trans != NULL) {
		if (mail_index_transaction_commit(&new_trans) < 0) {
			mailbox_set_index_error(box);
			return -1;
		}
	}
	return 0;
}

int mdbox_mailbox_create_indexes(struct mailbox *box,
				 const struct mailbox_update *update,
				 struct mail_index_transaction *trans)
{
	struct mdbox_mailbox *mbox = MDBOX_MAILBOX(box);
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

void mdbox_set_mailbox_corrupted(struct mailbox *box)
{
	struct mdbox_storage *mstorage = MDBOX_STORAGE(box->storage);

	mdbox_storage_set_corrupted(mstorage);
}

void mdbox_set_file_corrupted(struct dbox_file *file)
{
	struct mdbox_storage *mstorage = MDBOX_DBOX_STORAGE(file->storage);

	mdbox_storage_set_corrupted(mstorage);
}

static int
mdbox_mailbox_get_guid(struct mdbox_mailbox *mbox, guid_128_t guid_r)
{
	const struct mail_index_header *idx_hdr;
	struct mdbox_index_header hdr;
	bool need_resize;
	int ret = 0;

	i_assert(!mbox->creating);

	/* there's a race condition between mkdir and getting the mailbox GUID.
	   normally this is handled by mdbox syncing, but GUID can be looked up
	   without syncing. when we detect this situation we'll try to finish
	   creating the indexes first, which usually means just waiting for
	   the sync lock to get unlocked by the other process creating them. */
	idx_hdr = mail_index_get_header(mbox->box.view);
	if (idx_hdr->uid_validity == 0 && idx_hdr->next_uid == 1) {
		if (dbox_mailbox_create_indexes(&mbox->box, NULL) < 0)
			return -1;
	}

	if (mdbox_read_header(mbox, &hdr, &need_resize) < 0)
		i_zero(&hdr);

	if (guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (mdbox_write_index_header(&mbox->box, NULL, NULL) < 0 ||
		    mdbox_read_header(mbox, &hdr, &need_resize) < 0)
			ret = -1;
	}
	if (ret == 0)
		memcpy(guid_r, hdr.mailbox_guid, GUID_128_SIZE);
	return ret;
}

static int
mdbox_mailbox_get_metadata(struct mailbox *box,
			   enum mailbox_metadata_items items,
			   struct mailbox_metadata *metadata_r)
{
	struct mdbox_mailbox *mbox = MDBOX_MAILBOX(box);

	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		if (mdbox_mailbox_get_guid(mbox, metadata_r->guid) < 0)
			return -1;
	}
	return 0;
}

static int
mdbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (mdbox_write_index_header(box, update, NULL) < 0)
		return -1;
	return index_storage_mailbox_update_common(box, update);
}

struct mail_storage mdbox_storage = {
	.name = MDBOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA,
	.event_category = &event_category_mdbox,

	.v = {
                mdbox_get_setting_parser_info,
		mdbox_storage_alloc,
		mdbox_storage_create,
		mdbox_storage_destroy,
		NULL,
		dbox_storage_get_list_settings,
		mdbox_storage_autodetect,
		mdbox_mailbox_alloc,
		mdbox_purge,
		NULL,
	}
};

struct mailbox mdbox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		mdbox_mailbox_open,
		mdbox_mailbox_close,
		index_storage_mailbox_free,
		dbox_mailbox_create,
		mdbox_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		mdbox_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		index_storage_list_index_has_changed,
		index_storage_list_index_update_sync,
		mdbox_storage_sync_init,
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
		mdbox_save_alloc,
		mdbox_save_begin,
		dbox_save_continue,
		mdbox_save_finish,
		mdbox_save_cancel,
		mdbox_copy,
		mdbox_transaction_save_commit_pre,
		mdbox_transaction_save_commit_post,
		mdbox_transaction_save_rollback,
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
