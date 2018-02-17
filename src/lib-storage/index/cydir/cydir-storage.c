/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-copy.h"
#include "index-mail.h"
#include "mailbox-list-private.h"
#include "cydir-sync.h"
#include "cydir-storage.h"

#include <sys/stat.h>

extern struct mail_storage cydir_storage;
extern struct mailbox cydir_mailbox;

static struct mail_storage *cydir_storage_alloc(void)
{
	struct cydir_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("cydir storage", 512+256);
	storage = p_new(pool, struct cydir_storage, 1);
	storage->storage = cydir_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static void
cydir_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = CYDIR_SUBSCRIPTION_FILE_NAME;
}

static struct mailbox *
cydir_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
{
	struct cydir_mailbox *mbox;
	pool_t pool;

	/* cydir can't work without index files */
	flags &= ~MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("cydir mailbox", 1024*3);
	mbox = p_new(pool, struct cydir_mailbox, 1);
	mbox->box = cydir_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &cydir_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = CYDIR_STORAGE(storage);
	return &mbox->box;
}

static int cydir_mailbox_open(struct mailbox *box)
{
	const char *box_path = mailbox_get_path(box);
	struct stat st;

	if (stat(box_path, &st) == 0) {
		/* exists, open it */
	} else if (errno == ENOENT) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	} else if (errno == EACCES) {
		mailbox_set_critical(box, "%s",
			mail_error_eacces_msg("stat", box_path));
		return -1;
	} else {
		mailbox_set_critical(box, "stat(%s) failed: %m", box_path);
		return -1;
	}
	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;
	mail_index_set_fsync_mode(box->index,
				  box->storage->set->parsed_fsync_mode,
				  MAIL_INDEX_FSYNC_MASK_APPENDS |
				  MAIL_INDEX_FSYNC_MASK_EXPUNGES);
	return 0;
}

static int
cydir_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		     bool directory)
{
	int ret;

	if ((ret = index_storage_mailbox_create(box, directory)) <= 0)
		return ret;

	return update == NULL ? 0 :
		index_storage_mailbox_update(box, update);
}

static void cydir_notify_changes(struct mailbox *box)
{
	if (box->notify_callback == NULL)
		mailbox_watch_remove_all(box);
	else
		mailbox_watch_add(box, mailbox_get_path(box));
}

struct mail_storage cydir_storage = {
	.name = CYDIR_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_FILE_PER_MSG |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA,

	.v = {
		NULL,
		cydir_storage_alloc,
		NULL,
		index_storage_destroy,
		NULL,
		cydir_storage_get_list_settings,
		NULL,
		cydir_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox cydir_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		cydir_mailbox_open,
		index_storage_mailbox_close,
		index_storage_mailbox_free,
		cydir_mailbox_create,
		index_storage_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		index_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		index_storage_list_index_has_changed,
		index_storage_list_index_update_sync,
		cydir_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		cydir_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		index_mail_alloc,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		cydir_save_alloc,
		cydir_save_begin,
		cydir_save_continue,
		cydir_save_finish,
		cydir_save_cancel,
		mail_storage_copy,
		cydir_transaction_save_commit_pre,
		cydir_transaction_save_commit_post,
		cydir_transaction_save_rollback,
		index_storage_is_inconsistent
	}
};
