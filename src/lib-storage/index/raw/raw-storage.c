/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

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

struct mail_user *
raw_storage_create_from_set(const struct setting_parser_info *set_info,
			    const struct mail_user_settings *set)
{
	struct mail_user *user;
	struct mail_namespace *ns;
	struct mail_namespace_settings *ns_set;
	struct mail_storage_settings *mail_set;
	const char *error;

	user = mail_user_alloc("raw mail user", set_info, set);
	user->autocreated = TRUE;
	mail_user_set_home(user, "/");
	if (mail_user_init(user, &error) < 0)
		i_fatal("Raw user initialization failed: %s", error);

	ns_set = p_new(user->pool, struct mail_namespace_settings, 1);
	ns_set->name = "raw-storage";
	ns_set->location = ":LAYOUT=none";
	ns_set->separator = "/";

	ns = mail_namespaces_init_empty(user);
	/* raw storage doesn't have INBOX. We especially don't want LIST to
	   return INBOX. */
	ns->flags &= ~NAMESPACE_FLAG_INBOX_USER;
	ns->flags |= NAMESPACE_FLAG_NOQUOTA | NAMESPACE_FLAG_NOACL;
	ns->set = ns_set;
	/* absolute paths are ok with raw storage */
	mail_set = p_new(user->pool, struct mail_storage_settings, 1);
	*mail_set = *ns->mail_set;
	mail_set->mail_full_filesystem_access = TRUE;
	ns->mail_set = mail_set;

	if (mail_storage_create(ns, "raw", 0, &error) < 0)
		i_fatal("Couldn't create internal raw storage: %s", error);
	return user;
}

static int ATTR_NULL(2, 3)
raw_mailbox_alloc_common(struct mail_user *user, struct istream *input,
			 const char *path, time_t received_time,
			 const char *envelope_sender, struct mailbox **box_r)
{
	struct mail_namespace *ns = user->namespaces;
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	const char *name;

	name = path != NULL ? path : i_stream_get_name(input);
	box = *box_r = mailbox_alloc(ns->list, name,
				     MAILBOX_FLAG_NO_INDEX_FILES);
	if (input != NULL) {
		if (mailbox_open_stream(box, input) < 0)
			return -1;
	} else {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (mailbox_sync(box, 0) < 0)
		return -1;

	i_assert(strcmp(box->storage->name, RAW_STORAGE_NAME) == 0);
	raw_box = (struct raw_mailbox *)box;
	raw_box->envelope_sender = envelope_sender;
	raw_box->mtime = received_time;
	return 0;
}

int raw_mailbox_alloc_stream(struct mail_user *user, struct istream *input,
			     time_t received_time, const char *envelope_sender,
			     struct mailbox **box_r)
{
	return raw_mailbox_alloc_common(user, input, NULL, received_time,
					envelope_sender, box_r);
}

int raw_mailbox_alloc_path(struct mail_user *user, const char *path,
			   time_t received_time, const char *envelope_sender,
			   struct mailbox **box_r)
{
	return raw_mailbox_alloc_common(user, NULL, path, received_time,
					envelope_sender, box_r);
}

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
		  const char *vname, enum mailbox_flags flags)
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

	index_storage_mailbox_alloc(&mbox->box, vname, flags, "dovecot.index");

	mbox->mtime = mbox->ctime = (time_t)-1;
	mbox->storage = (struct raw_storage *)storage;
	mbox->size = (uoff_t)-1;
	return &mbox->box;
}

static int raw_mailbox_open(struct mailbox *box)
{
	struct raw_mailbox *mbox = (struct raw_mailbox *)box;
	const char *path;
	int fd;

	if (box->input != NULL) {
		mbox->mtime = mbox->ctime = ioloop_time;
		return index_storage_mailbox_open(box, FALSE);
	}

	path = box->_path = box->name;
	mbox->have_filename = TRUE;
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (ENOTFOUND(errno)) {
			mail_storage_set_error(box->storage,
				MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		} else if (!mail_storage_set_error_from_errno(box->storage)) {
			mail_storage_set_critical(box->storage,
				"open(%s) failed: %m", path);
		}
		return -1;
	}
	box->input = i_stream_create_fd(fd, MAIL_READ_FULL_BLOCK_SIZE, TRUE);
	i_stream_set_name(box->input, path);
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
		MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA,

	.v = {
		NULL,
		raw_storage_alloc,
		NULL,
		index_storage_destroy,
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
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		raw_mailbox_open,
		index_storage_mailbox_close,
		index_storage_mailbox_free,
		raw_mailbox_create,
		raw_mailbox_update,
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
		raw_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		raw_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		index_mail_alloc,
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
		NULL,
		NULL,
		index_storage_is_inconsistent
	}
};
