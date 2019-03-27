/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fs-api.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mail-search-build.h"
#include "mailbox-list-private.h"
#include "index-pop3-uidl.h"
#include "dbox-mail.h"
#include "dbox-save.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"
#include "sdbox-storage.h"

extern struct mail_storage dbox_storage, sdbox_storage;
extern struct mailbox sdbox_mailbox;
extern struct dbox_storage_vfuncs sdbox_dbox_storage_vfuncs;

static struct event_category event_category_sdbox = {
	.name = "sdbox",
	.parent = &event_category_storage,
};

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

static int sdbox_storage_create(struct mail_storage *_storage,
				struct mail_namespace *ns,
				const char **error_r)
{
	struct dbox_storage *storage = DBOX_STORAGE(_storage);
	enum fs_properties props;

	if (dbox_storage_create(_storage, ns, error_r) < 0)
		return -1;

	if (storage->attachment_fs != NULL) {
		props = fs_get_properties(storage->attachment_fs);
		if ((props & FS_PROPERTY_RENAME) == 0) {
			*error_r = "mail_attachment_fs: "
				"Backend doesn't support renaming";
			return -1;
		}
	}
	return 0;
}

static const char *
sdbox_storage_find_root_dir(const struct mail_namespace *ns)
{
	bool debug = ns->mail_set->mail_debug;
	const char *home, *path;

	if (ns->owner != NULL &&
	    mail_user_get_home(ns->owner, &home) > 0) {
		path = t_strconcat(home, "/sdbox", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_debug("sdbox: root exists (%s)", path);
			return path;
		} 
		if (debug)
			i_debug("sdbox: access(%s, rwx): failed: %m", path);
	}
	return NULL;
}

static bool sdbox_storage_autodetect(const struct mail_namespace *ns,
				     struct mailbox_list_settings *set)
{
	bool debug = ns->mail_set->mail_debug;
	struct stat st;
	const char *path, *root_dir;

	if (set->root_dir != NULL)
		root_dir = set->root_dir;
	else {
		root_dir = sdbox_storage_find_root_dir(ns);
		if (root_dir == NULL) {
			if (debug)
				i_debug("sdbox: couldn't find root dir");
			return FALSE;
		}
	}

	/* NOTE: this check works for mdbox as well. we'll rely on the
	   autodetect ordering to catch mdbox before we get here. */
	path = t_strconcat(root_dir, "/"DBOX_MAILBOX_DIR_NAME, NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_debug("sdbox autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_debug("sdbox autodetect: %s not a directory", path);
		return FALSE;
	}

	set->root_dir = root_dir;
	dbox_storage_get_list_settings(ns, set);
	return TRUE;
}

static struct mailbox *
sdbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
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

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS |
		MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;

	mbox->storage = SDBOX_STORAGE(storage);
	return &mbox->box;
}

int sdbox_read_header(struct sdbox_mailbox *mbox,
		      struct sdbox_index_header *hdr, bool log_error,
		      bool *need_resize_r)
{
	struct mail_index_view *view;
	const void *data;
	size_t data_size;
	int ret = 0;

	i_assert(mbox->box.opened);

	view = mail_index_view_open(mbox->box.index);
	mail_index_get_header_ext(view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < SDBOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->box.creating || data_size != 0)) {
		if (log_error) {
			mailbox_set_critical(&mbox->box,
				"sdbox: Invalid dbox header size");
		}
		ret = -1;
	} else {
		i_zero(hdr);
		memcpy(hdr, data, I_MIN(data_size, sizeof(*hdr)));
		if (guid_128_is_empty(hdr->mailbox_guid))
			ret = -1;
		else {
			/* data is valid. remember it in case mailbox
			   is being reset */
			mail_index_set_ext_init_data(mbox->box.index,
						     mbox->hdr_ext_id,
						     hdr, sizeof(*hdr));
		}
	}
	mail_index_view_close(&view);
	*need_resize_r = data_size < sizeof(*hdr);
	return ret;
}

static void sdbox_update_header(struct sdbox_mailbox *mbox,
				struct mail_index_transaction *trans,
				const struct mailbox_update *update)
{
	struct sdbox_index_header hdr, new_hdr;
	bool need_resize;

	if (sdbox_read_header(mbox, &hdr, TRUE, &need_resize) < 0) {
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

	if (need_resize) {
		mail_index_ext_resize_hdr(trans, mbox->hdr_ext_id,
					  sizeof(new_hdr));
	}
	if (memcmp(&hdr, &new_hdr, sizeof(hdr)) != 0) {
		mail_index_update_header_ext(trans, mbox->hdr_ext_id, 0,
					     &new_hdr, sizeof(new_hdr));
	}
	memcpy(mbox->mailbox_guid, new_hdr.mailbox_guid,
	       sizeof(mbox->mailbox_guid));
}

int sdbox_mailbox_create_indexes(struct mailbox *box,
				 const struct mailbox_update *update,
				 struct mail_index_transaction *trans)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(box);
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

	if (box->inbox_user && box->creating) {
		/* initialize pop3-uidl header when creating mailbox
		   (not on mailbox_update()) */
		index_pop3_uidl_set_max_uid(box, trans, 0);
	}

	sdbox_update_header(mbox, trans, update);
	if (new_trans != NULL) {
		if (mail_index_transaction_commit(&new_trans) < 0) {
			mailbox_set_index_error(box);
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
			guid_128_to_string(file->mbox->mailbox_guid),
			file->uid);
}

void sdbox_set_mailbox_corrupted(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(box);
	struct sdbox_index_header hdr;
	bool need_resize;

	if (sdbox_read_header(mbox, &hdr, TRUE, &need_resize) < 0 ||
	    hdr.rebuild_count == 0)
		mbox->corrupted_rebuild_count = 1;
	else
		mbox->corrupted_rebuild_count = hdr.rebuild_count;
}

static void sdbox_set_file_corrupted(struct dbox_file *_file)
{
	struct sdbox_file *file = (struct sdbox_file *)_file;

	sdbox_set_mailbox_corrupted(&file->mbox->box);
}

static int sdbox_mailbox_alloc_index(struct sdbox_mailbox *mbox)
{
	struct sdbox_index_header hdr;

	if (index_storage_mailbox_alloc_index(&mbox->box) < 0)
		return -1;

	mbox->hdr_ext_id =
		mail_index_ext_register(mbox->box.index, "dbox-hdr",
					sizeof(struct sdbox_index_header), 0, 0);
	/* set the initialization data in case the mailbox is created */
	i_zero(&hdr);
	guid_128_generate(hdr.mailbox_guid);
	mail_index_set_ext_init_data(mbox->box.index, mbox->hdr_ext_id,
				     &hdr, sizeof(hdr));
	return 0;
}

static int sdbox_mailbox_open(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(box);
	struct sdbox_index_header hdr;
	bool need_resize;
	time_t path_ctime;

	if (dbox_mailbox_check_existence(box, &path_ctime) < 0)
		return -1;

	if (sdbox_mailbox_alloc_index(mbox) < 0)
		return -1;

	if (dbox_mailbox_open(box, path_ctime) < 0)
		return -1;

	if (box->creating) {
		/* wait for mailbox creation to initialize the index */
		return 0;
	}

	/* get/generate mailbox guid */
	if (sdbox_read_header(mbox, &hdr, FALSE, &need_resize) < 0) {
		/* looks like the mailbox is corrupted */
		(void)sdbox_sync(mbox, SDBOX_SYNC_FLAG_FORCE);
		if (sdbox_read_header(mbox, &hdr, TRUE, &need_resize) < 0)
			i_zero(&hdr);
	}

	if (guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (sdbox_mailbox_create_indexes(box, NULL, NULL) < 0 ||
		    sdbox_read_header(mbox, &hdr, TRUE, &need_resize) < 0)
			return -1;
	}
	memcpy(mbox->mailbox_guid, hdr.mailbox_guid,
	       sizeof(mbox->mailbox_guid));
	return 0;
}

static void sdbox_mailbox_close(struct mailbox *box)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(box);

	if (mbox->corrupted_rebuild_count != 0)
		(void)sdbox_sync(mbox, 0);
	index_storage_mailbox_close(box);
}

static int
sdbox_mailbox_create(struct mailbox *box,
		     const struct mailbox_update *update, bool directory)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(box);
	struct sdbox_index_header hdr;
	bool need_resize;

	if (dbox_mailbox_create(box, update, directory) < 0)
		return -1;
	if (directory || !guid_128_is_empty(mbox->mailbox_guid))
		return 0;

	/* another process just created the mailbox. read the mailbox_guid. */
	if (sdbox_read_header(mbox, &hdr, FALSE, &need_resize) < 0) {
		mailbox_set_critical(box,
			"sdbox: Failed to read newly created dbox header");
		return -1;
	}
	memcpy(mbox->mailbox_guid, hdr.mailbox_guid,
	       sizeof(mbox->mailbox_guid));
	i_assert(!guid_128_is_empty(mbox->mailbox_guid));
	return 0;
}

static int
sdbox_mailbox_get_metadata(struct mailbox *box,
			   enum mailbox_metadata_items items,
			   struct mailbox_metadata *metadata_r)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(box);

	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		memcpy(metadata_r->guid, mbox->mailbox_guid,
		       sizeof(metadata_r->guid));
	}
	return 0;
}

static int
dbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (sdbox_mailbox_create_indexes(box, update, NULL) < 0)
		return -1;
	return index_storage_mailbox_update_common(box, update);
}

struct mail_storage sdbox_storage = {
	.name = SDBOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_FILE_PER_MSG |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA |
		MAIL_STORAGE_CLASS_FLAG_STUBS,
	.event_category = &event_category_sdbox,

	.v = {
                NULL,
		sdbox_storage_alloc,
		sdbox_storage_create,
		dbox_storage_destroy,
		NULL,
		dbox_storage_get_list_settings,
		sdbox_storage_autodetect,
		sdbox_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mail_storage dbox_storage = {
	.name = "dbox", /* alias */
	.class_flags = MAIL_STORAGE_CLASS_FLAG_FILE_PER_MSG,
	.event_category = &event_category_sdbox,

	.v = {
		NULL,
		sdbox_storage_alloc,
		sdbox_storage_create,
		dbox_storage_destroy,
		NULL,
		dbox_storage_get_list_settings,
		sdbox_storage_autodetect,
		sdbox_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox sdbox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		sdbox_mailbox_open,
		sdbox_mailbox_close,
		index_storage_mailbox_free,
		sdbox_mailbox_create,
		dbox_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		sdbox_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		index_storage_list_index_has_changed,
		index_storage_list_index_update_sync,
		sdbox_storage_sync_init,
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
		sdbox_save_alloc,
		sdbox_save_begin,
		dbox_save_continue,
		sdbox_save_finish,
		sdbox_save_cancel,
		sdbox_copy,
		sdbox_transaction_save_commit_pre,
		sdbox_transaction_save_commit_post,
		sdbox_transaction_save_rollback,
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
