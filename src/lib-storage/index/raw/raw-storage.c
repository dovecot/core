/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "mailbox-list-private.h"
#include "raw-sync.h"
#include "raw-storage.h"

extern struct mail_storage raw_storage;
extern struct mailbox raw_mailbox;

static struct mail_storage *raw_storage_alloc(void)
{
	struct raw_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("raw storage", 512+256);
	storage = p_new(pool, struct raw_storage, 1);
	storage->storage = raw_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static void
raw_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
			      struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = RAW_SUBSCRIPTION_FILE_NAME;
}

static struct mailbox *
raw_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		  const char *name, enum mailbox_flags flags)
{
	struct raw_mailbox *mbox;
	pool_t pool;

	flags |= MAILBOX_FLAG_READONLY | MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("raw mailbox", 1024*3);
	mbox = p_new(pool, struct raw_mailbox, 1);
	mbox->box = raw_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &raw_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, name, flags, NULL);

	mbox->mtime = mbox->ctime = (time_t)-1;
	mbox->storage = (struct raw_storage *)storage;
	mbox->size = (uoff_t)-1;
	return &mbox->box;
}

static int raw_mailbox_open(struct mailbox *box)
{
	struct raw_mailbox *mbox = (struct raw_mailbox *)box;
	int fd;

	if (box->input != NULL) {
		mbox->mtime = mbox->ctime = ioloop_time;
		return index_storage_mailbox_open(box, FALSE);
	}

	box->path = box->name;
	mbox->have_filename = TRUE;
	fd = open(box->path, O_RDONLY);
	if (fd == -1) {
		if (ENOTFOUND(errno)) {
			mail_storage_set_error(box->storage,
				MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
		} else if (!mail_storage_set_error_from_errno(box->storage)) {
			mail_storage_set_critical(box->storage,
				"open(%s) failed: %m", box->path);
		}
		return -1;
	}
	box->input = i_stream_create_fd(fd, MAIL_READ_FULL_BLOCK_SIZE, TRUE);
	i_stream_set_name(box->input, box->path);
	i_stream_set_init_buffer_size(box->input, MAIL_READ_FULL_BLOCK_SIZE);
	return index_storage_mailbox_open(box, FALSE);
}

static int
raw_mailbox_create(struct mailbox *box,
		   const struct mailbox_update *update ATTR_UNUSED,
		   bool directory ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Raw mailbox creation isn't supported");
	return -1;
}

static int
raw_mailbox_update(struct mailbox *box,
		   const struct mailbox_update *update ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Raw mailbox update isn't supported");
	return -1;
}

static void raw_notify_changes(struct mailbox *box ATTR_UNUSED)
{
}

struct mail_storage raw_storage = {
	.name = RAW_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_MAILBOX_IS_FILE |
		MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS,

	.v = {
		NULL,
		raw_storage_alloc,
		NULL,
		NULL,
		NULL,
		raw_storage_get_list_settings,
		NULL,
		raw_mailbox_alloc,
		NULL
	}
};

struct mailbox raw_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		raw_mailbox_open,
		index_storage_mailbox_close,
		index_storage_mailbox_free,
		raw_mailbox_create,
		raw_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		NULL,
		NULL,
		NULL,
		raw_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		raw_notify_changes,
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
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		mail_storage_copy,
		NULL,
		index_storage_is_inconsistent
	}
};
