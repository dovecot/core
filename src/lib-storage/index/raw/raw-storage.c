/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "raw-sync.h"
#include "raw-storage.h"

#define RAW_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, raw_mailbox_list_module)

extern struct mail_storage raw_storage;
extern struct mailbox raw_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(raw_mailbox_list_module,
				  &mailbox_list_module_register);

static int raw_list_delete_mailbox(struct mailbox_list *list, const char *name);
static int raw_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				    const char *dir, const char *fname,
				    enum mailbox_list_file_type type,
				    enum mailbox_info_flags *flags);

static int
raw_get_list_settings(struct mailbox_list_settings *list_set,
		      const char *data, enum mail_storage_flags flags,
		      const char **layout_r, const char **error_r)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;

	*layout_r = "fs";

	memset(list_set, 0, sizeof(*list_set));
	list_set->subscription_fname = RAW_SUBSCRIPTION_FILE_NAME;
	list_set->maildir_name = "";

	if (data == NULL || *data == '\0' || *data == ':') {
		/* we won't do any guessing for this format. */
		if (debug)
			i_info("raw: mailbox location not given");
		*error_r = "Root mail directory not given";
		return -1;
	}

	if (debug)
		i_info("raw: data=%s", data);
	return mailbox_list_settings_parse(data, list_set, layout_r, NULL,
					   error_r);
}

static struct mail_storage *raw_alloc(void)
{
	struct raw_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("raw storage", 512+256);
	storage = p_new(pool, struct raw_storage, 1);
	storage->storage = raw_storage;
	storage->storage.pool = pool;

	return &storage->storage;
}

static int raw_create(struct mail_storage *_storage, const char *data,
		      const char **error_r)
{
	struct raw_storage *storage = (struct raw_storage *)_storage;
	struct mailbox_list_settings list_set;
	struct stat st;
	const char *layout;

	if (raw_get_list_settings(&list_set, data, _storage->flags,
				  &layout, error_r) < 0)
		return -1;
	list_set.mail_storage_flags = &_storage->flags;
	list_set.lock_method = &_storage->lock_method;

	if (stat(list_set.root_dir, &st) < 0) {
		if (errno != ENOENT) {
			*error_r = t_strdup_printf("stat(%s) failed: %m",
						   list_set.root_dir);
		} else {
			*error_r = t_strdup_printf(
				"Root mail directory doesn't exist: %s",
				list_set.root_dir);
		}
		return -1;
	}

	if (mailbox_list_alloc(layout, &_storage->list, error_r) < 0)
		return -1;
	storage->list_module_ctx.super = _storage->list->v;
	_storage->list->v.iter_is_mailbox = raw_list_iter_is_mailbox;
	_storage->list->v.delete_mailbox = raw_list_delete_mailbox;

	MODULE_CONTEXT_SET_FULL(_storage->list, raw_mailbox_list_module,
				storage, &storage->list_module_ctx);

	/* finish list init after we've overridden vfuncs */
	mailbox_list_init(_storage->list, _storage->ns, &list_set,
			  mail_storage_get_list_flags(_storage->flags));
	return 0;
}

static int
raw_mailbox_open_input(struct mail_storage *storage, const char *name,
		       const char *path, struct istream **input_r)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (ENOTFOUND(errno)) {
			mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		} else if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
						  "open(%s) failed: %m", path);
		}
		return -1;
	}
	*input_r = i_stream_create_fd(fd, MAIL_READ_BLOCK_SIZE, TRUE);
	return 0;
}

static struct mailbox *
raw_mailbox_open(struct mail_storage *_storage, const char *name,
		 struct istream *input, enum mailbox_open_flags flags)
{
	struct raw_storage *storage = (struct raw_storage *)_storage;
	struct raw_mailbox *mbox;
	const char *path;
	pool_t pool;
	bool stream = input != NULL;

	flags |= MAILBOX_OPEN_READONLY | MAILBOX_OPEN_NO_INDEX_FILES;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (input != NULL)
		i_stream_ref(input);
	else {
		if (raw_mailbox_open_input(_storage, name, path, &input) < 0)
			return NULL;
	}

	pool = pool_alloconly_create("raw mailbox", 1024+512);
	mbox = p_new(pool, struct raw_mailbox, 1);
	mbox->ibox.box = raw_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = &storage->storage;
	mbox->ibox.mail_vfuncs = &raw_mail_vfuncs;
	mbox->ibox.index = index_storage_alloc(_storage, name, flags, NULL);

	mbox->storage = storage;
	mbox->path = p_strdup(pool, path);
	mbox->input = input;

	if (stream)
		mbox->mtime = mbox->ctime = ioloop_time;
	else
		mbox->mtime = mbox->ctime = (time_t)-1;
	mbox->size = (uoff_t)-1;

	index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	return &mbox->ibox.box;
}

static int raw_mailbox_close(struct mailbox *box)
{
	struct raw_mailbox *mbox = (struct raw_mailbox *)box;

	i_stream_unref(&mbox->input);
	return index_storage_mailbox_close(box);
}

static int raw_mailbox_create(struct mail_storage *storage,
			      const char *name ATTR_UNUSED,
			      bool directory ATTR_UNUSED)
{
	mail_storage_set_error(storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Raw mailbox creation isn't supported");
	return -1;
}

static int raw_list_delete_mailbox(struct mailbox_list *list,
				   const char *name ATTR_UNUSED)
{
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
			       "Raw mailbox deletion isn't supported");
	return -1;
}

static void raw_notify_changes(struct mailbox *box ATTR_UNUSED)
{
}

static int raw_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				    const char *dir, const char *fname,
				    enum mailbox_list_file_type type,
				    enum mailbox_info_flags *flags_r)
{
	struct mail_storage *storage = RAW_LIST_CONTEXT(ctx->list);
	const char *path;
	struct stat st;

	/* try to avoid stat() with these checks */
	if (type == MAILBOX_LIST_FILE_TYPE_DIR) {
		*flags_r = MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		return 1;
	}
	if (type != MAILBOX_LIST_FILE_TYPE_SYMLINK &&
	    type != MAILBOX_LIST_FILE_TYPE_UNKNOWN &&
	    (ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0) {
		*flags_r = MAILBOX_NOINFERIORS;
		return 1;
	}

	/* need to stat() then */
	path = t_strconcat(dir, "/", fname, NULL);
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			*flags_r = MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		else
			*flags_r = MAILBOX_NOINFERIORS;
		return 1;
	} else if (errno == EACCES || errno == ELOOP) {
		*flags_r = MAILBOX_NOSELECT;
		return 1;
	} else if (ENOTFOUND(errno)) {
		*flags_r = MAILBOX_NONEXISTENT;
		return 0;
	} else {
		mail_storage_set_critical(storage, "stat(%s) failed: %m", path);
		return -1;
	}
}

static void raw_class_init(void)
{
	raw_transaction_class_init();
}

static void raw_class_deinit(void)
{
	raw_transaction_class_deinit();
}

struct mail_storage raw_storage = {
	MEMBER(name) RAW_STORAGE_NAME,
	MEMBER(mailbox_is_file) TRUE,

	{
		raw_class_init,
		raw_class_deinit,
		raw_alloc,
		raw_create,
		index_storage_destroy,
		NULL,
		raw_mailbox_open,
		raw_mailbox_create
	}
};

struct mailbox raw_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		raw_mailbox_close,
		index_storage_get_status,
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
		index_keywords_create,
		index_keywords_free,
		index_storage_get_uids,
		index_storage_get_expunged_uids,
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
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
