/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "restrict-access.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "mbox-storage.h"
#include "mbox-lock.h"
#include "mbox-file.h"
#include "mbox-sync-private.h"
#include "istream-raw-mbox.h"
#include "mail-copy.h"
#include "index-mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* How often to touch the dotlock file when using KEEP_LOCKED flag */
#define MBOX_LOCK_TOUCH_MSECS (10*1000)

/* Assume that if atime < mtime, there are new mails. If it's good enough for
   UW-IMAP, it's good enough for us. */
#define STAT_GET_MARKED(st) \
	((st).st_size == 0 ? MAILBOX_UNMARKED : \
	 (st).st_atime < (st).st_mtime ? MAILBOX_MARKED : MAILBOX_UNMARKED)

#define MBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mbox_mailbox_list_module)

struct mbox_mailbox_list {
	union mailbox_list_module_context module_ctx;
	const struct mbox_settings *set;
};

/* NOTE: must be sorted for istream-header-filter. Note that it's not such
   a good idea to change this list, as the messages will then change from
   client's point of view. So if you do it, change all mailboxes' UIDVALIDITY
   so all caches are reset. */
const char *mbox_hide_headers[] = {
	"Content-Length",
	"Status",
	"X-IMAP",
	"X-IMAPbase",
	"X-Keywords",
	"X-Status",
	"X-UID"
};
unsigned int mbox_hide_headers_count = N_ELEMENTS(mbox_hide_headers);

/* A bit ugly duplification of the above list. It's safe to modify this list
   without bad side effects, just keep the list sorted. */
const char *mbox_save_drop_headers[] = {
	"Content-Length",
	"Status",
	"X-Delivery-ID"
	"X-IMAP",
	"X-IMAPbase",
	"X-Keywords",
	"X-Status",
	"X-UID"
};
unsigned int mbox_save_drop_headers_count = N_ELEMENTS(mbox_save_drop_headers);

extern struct mail_storage mbox_storage;
extern struct mailbox mbox_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(mbox_mailbox_list_module,
				  &mailbox_list_module_register);

int mbox_set_syscall_error(struct mbox_mailbox *mbox, const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		mail_storage_set_error(&mbox->storage->storage,
			MAIL_ERROR_NOSPACE, MAIL_ERRSTR_NO_SPACE);
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
					  "%s failed with mbox file %s: %m",
					  function, mbox->ibox.box.path);
	}
	return -1;
}

static const char *
mbox_list_get_path(struct mailbox_list *list, const char *name,
		   enum mailbox_list_path_type type)
{
	struct mbox_mailbox_list *mlist = MBOX_LIST_CONTEXT(list);
	const char *path, *p;

	path = mlist->module_ctx.super.get_path(list, name, type);
	if (type == MAILBOX_LIST_PATH_TYPE_CONTROL ||
	    type == MAILBOX_LIST_PATH_TYPE_INDEX) {
		if (name == NULL)
			return t_strconcat(path, "/"MBOX_INDEX_DIR_NAME, NULL);

		p = strrchr(path, '/');
		if (p == NULL)
			return "";

		return t_strconcat(t_strdup_until(path, p),
				   "/"MBOX_INDEX_DIR_NAME"/", p+1, NULL);
	}
	return path;
}

static struct mail_storage *mbox_storage_alloc(void)
{
	struct mbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("mbox storage", 512+256);
	storage = p_new(pool, struct mbox_storage, 1);
	storage->storage = mbox_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static int
mbox_storage_create(struct mail_storage *_storage, struct mail_namespace *ns,
		    const char **error_r ATTR_UNUSED)
{
	struct mbox_storage *storage = (struct mbox_storage *)_storage;
	const char *dir;

	storage->set = mail_storage_get_driver_settings(_storage);

	dir = mailbox_list_get_path(ns->list, NULL,
				    MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*dir != '\0') {
		_storage->temp_path_prefix = p_strconcat(_storage->pool, dir,
			"/", mailbox_list_get_temp_prefix(ns->list), NULL);
	}
	return 0;
}

static void mbox_storage_get_list_settings(const struct mail_namespace *ns,
					   struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = MBOX_SUBSCRIPTION_FILE_NAME;

	if (set->inbox_path == NULL) {
		set->inbox_path = t_strconcat(set->root_dir, "/inbox", NULL);
		if (ns->mail_set->mail_debug)
			i_debug("mbox: INBOX defaulted to %s", set->inbox_path);
	}
}

static bool mbox_is_file(const char *path, const char *name, bool debug)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		if (debug) {
			i_debug("mbox autodetect: %s: stat(%s) failed: %m",
				name, path);
		}
		return FALSE;
	}
	if (S_ISDIR(st.st_mode)) {
		if (debug) {
			i_debug("mbox autodetect: %s: is a directory (%s)",
			       name, path);
		}
		return FALSE;
	}
	if (access(path, R_OK|W_OK) < 0) {
		if (debug) {
			i_debug("mbox autodetect: %s: no R/W access (%s)",
			       name, path);
		}
		return FALSE;
	}

	if (debug)
		i_debug("mbox autodetect: %s: yes (%s)", name, path);
	return TRUE;
}

static bool mbox_is_dir(const char *path, const char *name, bool debug)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		if (debug) {
			i_debug("mbox autodetect: %s: stat(%s) failed: %m",
			       name, path);
		}
		return FALSE;
	}
	if (!S_ISDIR(st.st_mode)) {
		if (debug) {
			i_debug("mbox autodetect: %s: is not a directory (%s)",
			       name, path);
		}
		return FALSE;
	}
	if (access(path, R_OK|W_OK|X_OK) < 0) {
		if (debug) {
			i_debug("mbox autodetect: %s: no R/W/X access (%s)",
			       name, path);
		}
		return FALSE;
	}

	if (debug)
		i_debug("mbox autodetect: %s: yes (%s)", name, path);
	return TRUE;
}

static bool mbox_storage_is_root_dir(const char *dir, bool debug)
{
	if (mbox_is_dir(t_strconcat(dir, "/"MBOX_INDEX_DIR_NAME, NULL),
			"has "MBOX_INDEX_DIR_NAME"/", debug))
		return TRUE;
	if (mbox_is_file(t_strconcat(dir, "/inbox", NULL), "has inbox", debug))
		return TRUE;
	if (mbox_is_file(t_strconcat(dir, "/mbox", NULL), "has mbox", debug))
		return TRUE;
	return FALSE;
}

static const char *mbox_storage_find_root_dir(const struct mail_namespace *ns)
{
	bool debug = ns->mail_set->mail_debug;
	const char *home, *path;

	if (mail_user_get_home(ns->user, &home) <= 0) {
		if (debug)
			i_debug("maildir: Home directory not set");
		home = "";
	}

	path = t_strconcat(home, "/mail", NULL);
	if (mbox_storage_is_root_dir(path, debug))
		return path;

	path = t_strconcat(home, "/Mail", NULL);
	if (mbox_storage_is_root_dir(path, debug))
		return path;
	return NULL;
}

static const char *
mbox_storage_find_inbox_file(const char *user, bool debug)
{
	const char *path;

	path = t_strconcat("/var/mail/", user, NULL);
	if (access(path, R_OK|W_OK) == 0) {
		if (debug)
			i_debug("mbox: INBOX exists (%s)", path);
		return path;
	}
	if (debug)
		i_debug("mbox: INBOX: access(%s, rw) failed: %m", path);

	path = t_strconcat("/var/spool/mail/", user, NULL);
	if (access(path, R_OK|W_OK) == 0) {
		if (debug)
			i_debug("mbox: INBOX exists (%s)", path);
		return path;
	}
	if (debug)
		i_debug("mbox: INBOX: access(%s, rw) failed: %m", path);
	return NULL;
}

static bool mbox_storage_autodetect(const struct mail_namespace *ns,
				    struct mailbox_list_settings *set)
{
	bool debug = ns->mail_set->mail_debug;
	const char *root_dir, *inbox_path;

	root_dir = set->root_dir;
	inbox_path = set->inbox_path;

	if (root_dir != NULL) {
		if (inbox_path == NULL &&
		    mbox_is_file(root_dir, "INBOX file", debug)) {
			/* using location=<INBOX> */
			inbox_path = root_dir;
			root_dir = NULL;
		} else if (!mbox_storage_is_root_dir(root_dir, debug))
			return FALSE;
	}
	if (root_dir == NULL) {
		root_dir = mbox_storage_find_root_dir(ns);
		if (root_dir == NULL) {
			if (debug)
				i_debug("mbox: couldn't find root dir");
			return FALSE;
		}
	}
	if (inbox_path == NULL) {
		inbox_path = mbox_storage_find_inbox_file(ns->user->username,
							  debug);
	}
	set->root_dir = root_dir;
	set->inbox_path = inbox_path;

	mbox_storage_get_list_settings(ns, set);
	return TRUE;
}

static bool want_memory_indexes(struct mbox_storage *storage, const char *path)
{
	struct stat st;

	if (storage->set->mbox_min_index_size == 0)
		return FALSE;

	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			st.st_size = 0;
		else {
			mail_storage_set_critical(&storage->storage,
						  "stat(%s) failed: %m", path);
			return FALSE;
		}
	}
	return (uoff_t)st.st_size < storage->set->mbox_min_index_size;
}

static struct mailbox *
mbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		   const char *name, struct istream *input,
		   enum mailbox_flags flags)
{
	struct mbox_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("mbox mailbox", 1024+512);
	mbox = p_new(pool, struct mbox_mailbox, 1);
	mbox->ibox.box = mbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.box.storage = storage;
	mbox->ibox.box.list = list;
	mbox->ibox.mail_vfuncs = &mbox_mail_vfuncs;

	mbox->ibox.save_commit_pre = mbox_transaction_save_commit_pre;
	mbox->ibox.save_commit_post = mbox_transaction_save_commit_post;
	mbox->ibox.save_rollback = mbox_transaction_save_rollback;

	index_storage_mailbox_alloc(&mbox->ibox, name, input, flags,
				    MBOX_INDEX_PREFIX);

	mbox->storage = (struct mbox_storage *)storage;
	mbox->mbox_fd = -1;
	mbox->mbox_lock_type = F_UNLCK;
	mbox->mbox_ext_idx =
		mail_index_ext_register(mbox->ibox.index, "mbox",
					sizeof(mbox->mbox_hdr),
					sizeof(uint64_t), sizeof(uint64_t));
	mbox->md5hdr_ext_idx =
		mail_index_ext_register(mbox->ibox.index, "header-md5",
					0, 16, 1);

	if ((storage->flags & MAIL_STORAGE_FLAG_KEEP_HEADER_MD5) != 0)
		mbox->mbox_save_md5 = TRUE;
	return &mbox->ibox.box;
}

static int verify_inbox(struct mailbox_list *list)
{
	const char *inbox_path, *rootdir;
	int fd;

	inbox_path = mailbox_list_get_path(list, "INBOX",
					   MAILBOX_LIST_PATH_TYPE_MAILBOX);
	rootdir = mailbox_list_get_path(list, NULL,
					MAILBOX_LIST_PATH_TYPE_DIR);

	/* make sure inbox file itself exists */
	fd = open(inbox_path, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd == -1 && errno == EACCES) {
		/* try again with increased privileges */
		(void)restrict_access_use_priv_gid();
		fd = open(inbox_path, O_RDWR | O_CREAT | O_EXCL, 0660);
		restrict_access_drop_priv_gid();
	}
	if (fd != -1)
		(void)close(fd);
	else if (errno == ENOTDIR &&
		 strncmp(inbox_path, rootdir, strlen(rootdir)) == 0) {
		mailbox_list_set_critical(list,
			"mbox root directory can't be a file: %s "
			"(http://wiki.dovecot.org/MailLocation/Mbox)",
			rootdir);
		return -1;
	} else if (errno == EACCES) {
		mailbox_list_set_critical(list, "%s",
			mail_error_create_eacces_msg("open", inbox_path));
		return -1;
	} else if (errno != EEXIST) {
		mailbox_list_set_critical(list,
			"open(%s, O_CREAT) failed: %m", inbox_path);
		return -1;
	}

	return 0;
}

static void mbox_lock_touch_timeout(struct mbox_mailbox *mbox)
{
	mbox_dotlock_touch(mbox);
}

static int mbox_mailbox_open_existing(struct mbox_mailbox *mbox)
{
	struct mailbox *box = &mbox->ibox.box;
	const char *rootdir;

	if (access(box->path, R_OK|W_OK) < 0) {
		if (errno != EACCES) {
			mbox_set_syscall_error(mbox, "access()");
			return -1;
		}
		mbox->ibox.backend_readonly = TRUE;
	}
	mbox->ibox.move_to_memory =
		want_memory_indexes(mbox->storage, box->path);

	if (strcmp(box->name, "INBOX") == 0) {
		/* if INBOX isn't under the root directory, it's probably in
		   /var/mail and we want to allow privileged dotlocking */
		rootdir = mailbox_list_get_path(box->list, NULL,
						MAILBOX_LIST_PATH_TYPE_DIR);
		if (strncmp(box->path, rootdir, strlen(rootdir)) != 0)
			mbox->mbox_privileged_locking = TRUE;
	}
	if ((box->flags & MAILBOX_FLAG_KEEP_LOCKED) != 0) {
		if (mbox_lock(mbox, F_WRLCK, &mbox->mbox_global_lock_id) <= 0)
			return -1;

		if (mbox->mbox_dotlock != NULL) {
			mbox->keep_lock_to =
				timeout_add(MBOX_LOCK_TOUCH_MSECS,
					    mbox_lock_touch_timeout, mbox);
		}
	}
	return index_storage_mailbox_open(box);
}

static int mbox_mailbox_open(struct mailbox *box)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;
	struct stat st;
	int ret;

	if (box->input != NULL) {
		mbox->mbox_file_stream = box->input;
		mbox->ibox.backend_readonly = TRUE;
		mbox->no_mbox_file = TRUE;
		return 0;
	}

	if (strcmp(box->name, "INBOX") == 0 &&
	    (box->list->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		/* make sure INBOX exists */
		if (verify_inbox(box->list) < 0)
			return -1;
		return mbox_mailbox_open_existing(mbox);
	}

	if ((ret = stat(box->path, &st)) == 0 && !S_ISDIR(st.st_mode))
		return mbox_mailbox_open_existing(mbox);
	else if (ret == 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			t_strdup_printf("Mailbox isn't selectable: %s",
					box->name));
		return -1;
	} else if (ENOTFOUND(errno)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
		return -1;
	} else if (mail_storage_set_error_from_errno(box->storage)) {
		return -1;
	} else {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", box->path);
		return -1;
	}
}

static int
mbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;
	int ret;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}

	mbox->sync_hdr_update = update;
	ret = mbox_sync(mbox, MBOX_SYNC_HEADER | MBOX_SYNC_FORCE_SYNC |
			MBOX_SYNC_REWRITE);
	mbox->sync_hdr_update = NULL;
	return ret;
}

static int
mbox_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		    bool directory)
{
	int fd, ret;

	if (directory &&
	    (box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) == 0)
		return 0;

	/* create the mbox file */
	ret = mailbox_create_fd(box, box->path, O_RDWR | O_CREAT | O_EXCL, &fd);
	if (ret <= 0) {
		if (ret == 0) {
			mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
					       "Mailbox already exists");
		}
		return -1;
	}
	(void)close(fd);
	return update == NULL ? 0 : mbox_mailbox_update(box, update);
}

static void mbox_mailbox_close(struct mailbox *box)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;
	const struct mail_index_header *hdr;
	enum mbox_sync_flags sync_flags = 0;

	if (mbox->mbox_stream != NULL &&
	    istream_raw_mbox_is_corrupted(mbox->mbox_stream)) {
		/* clear the corruption by forcing a full resync */
		sync_flags |= MBOX_SYNC_UNDIRTY | MBOX_SYNC_FORCE_SYNC;
	}

	if (mbox->ibox.view != NULL) {
		hdr = mail_index_get_header(mbox->ibox.view);
		if ((hdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0 &&
		    !mbox->ibox.backend_readonly) {
			/* we've done changes to mbox which haven't been
			   written yet. do it now. */
			sync_flags |= MBOX_SYNC_REWRITE;
		}
	}
	if (sync_flags != 0 && !mbox->invalid_mbox_file)
		(void)mbox_sync(mbox, sync_flags);

	if (mbox->mbox_global_lock_id != 0)
		(void)mbox_unlock(mbox, mbox->mbox_global_lock_id);
	if (mbox->keep_lock_to != NULL)
		timeout_remove(&mbox->keep_lock_to);

        mbox_file_close(mbox);
	if (mbox->mbox_file_stream != NULL)
		i_stream_destroy(&mbox->mbox_file_stream);

	index_storage_mailbox_close(box);
}

static void
mbox_storage_get_status(struct mailbox *box, enum mailbox_status_items items,
			struct mailbox_status *status_r)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;

	index_storage_get_status(box, items, status_r);
	if ((items & STATUS_GUID) != 0) {
		memcpy(status_r->mailbox_guid, mbox->mbox_hdr.mailbox_guid,
		       sizeof(status_r->mailbox_guid));
	}
}

static void mbox_notify_changes(struct mailbox *box)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->ibox);
	else if (!mbox->no_mbox_file)
		index_mailbox_check_add(&mbox->ibox, mbox->ibox.box.path);
}

static bool
is_inbox_file(struct mailbox_list *list, const char *path, const char *fname)
{
	const char *inbox_path;

	if (strcasecmp(fname, "INBOX") != 0)
		return FALSE;

	inbox_path = mailbox_list_get_path(list, "INBOX",
					   MAILBOX_LIST_PATH_TYPE_MAILBOX);
	return strcmp(inbox_path, path) == 0;
}

static bool mbox_name_is_dotlock(const char *name)
{
	unsigned int len = strlen(name);

	return len >= 5 && strcmp(name + len - 5, ".lock") == 0;
}

static bool
mbox_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	struct mbox_mailbox_list *mlist = MBOX_LIST_CONTEXT(list);

	return mlist->module_ctx.super.is_valid_existing_name(list, name) &&
		!mbox_name_is_dotlock(name);
}

static bool
mbox_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	struct mbox_mailbox_list *mlist = MBOX_LIST_CONTEXT(list);

	return mlist->module_ctx.super.is_valid_create_name(list, name) &&
		!mbox_name_is_dotlock(name);
}

static int mbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				     const char *dir, const char *fname,
				     const char *mailbox_name ATTR_UNUSED,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags)
{
	const char *path, *root_dir;
	size_t len;
	struct stat st;

	if (strcmp(fname, MBOX_INDEX_DIR_NAME) == 0) {
		*flags |= MAILBOX_NOSELECT;
		return 0;
	}
	if (strcmp(fname, ctx->list->set.subscription_fname) == 0) {
		root_dir = mailbox_list_get_path(ctx->list, NULL,
						 MAILBOX_LIST_PATH_TYPE_DIR);
		if (strcmp(root_dir, dir) == 0) {
			*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			return 0;
		}
	}

	/* skip all .lock files */
	len = strlen(fname);
	if (len > 5 && strcmp(fname+len-5, ".lock") == 0) {
		*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;
	}

	/* try to avoid stat() with these checks */
	if (type == MAILBOX_LIST_FILE_TYPE_DIR) {
		*flags |= MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		return 1;
	}
	if (type != MAILBOX_LIST_FILE_TYPE_SYMLINK &&
	    type != MAILBOX_LIST_FILE_TYPE_UNKNOWN &&
	    (ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0) {
		*flags |= MAILBOX_NOINFERIORS;
		return 1;
	}

	/* need to stat() then */
	path = t_strconcat(dir, "/", fname, NULL);
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			*flags |= MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		else {
			*flags |= MAILBOX_NOINFERIORS | STAT_GET_MARKED(st);
			if (is_inbox_file(ctx->list, path, fname) &&
			    strcmp(fname, "INBOX") != 0) {
				/* it's possible for INBOX to have child
				   mailboxes as long as the inbox file itself
				   isn't in <mail root>/INBOX */
				*flags &= ~MAILBOX_NOINFERIORS;
			}
		}
		return 1;
	} else if (errno == ENOENT) {
		/* doesn't exist - probably a non-existing subscribed mailbox */
		*flags |= MAILBOX_NONEXISTENT;
		return 1;
	} else {
		/* non-selectable. probably either access denied, or symlink
		   destination not found. don't bother logging errors. */
		*flags |= MAILBOX_NOSELECT;
		return 0;
	}
}

static int mbox_list_delete_mailbox(struct mailbox_list *list,
				    const char *name)
{
	struct mbox_mailbox_list *mlist = MBOX_LIST_CONTEXT(list);
	struct stat st;
	const char *path, *index_dir;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (lstat(path, &st) < 0) {
		if (ENOTFOUND(errno)) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		} else if (!mailbox_list_set_error_from_errno(list)) {
			mailbox_list_set_critical(list,
				"lstat() failed for %s: %m", path);
		}
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		/* deleting a directory. allow it only if it doesn't contain
		   anything. Delete the ".imap" directory first in case there
		   have been indexes. */
		index_dir = mailbox_list_get_path(list, name,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
		index_dir = *index_dir == '\0' ? "" :
			t_strconcat(index_dir, "/"MBOX_INDEX_DIR_NAME, NULL);

		if (*index_dir != '\0' && rmdir(index_dir) < 0 &&
		    !ENOTFOUND(errno) && errno != ENOTEMPTY) {
			if (!mailbox_list_set_error_from_errno(list)) {
				mailbox_list_set_critical(list,
					"rmdir() failed for %s: %m", index_dir);
			}
			return -1;
		}

		if (rmdir(path) == 0)
			return 0;

		if (ENOTFOUND(errno)) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		} else if (errno == ENOTEMPTY) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				t_strdup_printf("Directory %s isn't empty, "
						"can't delete it.", name));
		} else if (!mailbox_list_set_error_from_errno(list)) {
			mailbox_list_set_critical(list,
				"rmdir() failed for %s: %m", path);
		}
		return -1;
	}

	/* delete index / control files first */
	if (mlist->module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	if (unlink(path) < 0) {
		if (ENOTFOUND(errno)) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		} else if (!mailbox_list_set_error_from_errno(list)) {
			mailbox_list_set_critical(list,
				"unlink() failed for %s: %m", path);
		}
		return -1;
	}

	return 0;
}

static void mbox_storage_add_list(struct mail_storage *storage,
				  struct mailbox_list *list)
{
	struct mbox_mailbox_list *mlist;

	mlist = p_new(list->pool, struct mbox_mailbox_list, 1);
	mlist->module_ctx.super = list->v;
	mlist->set = mail_storage_get_driver_settings(storage);

	if (strcmp(list->name, MAILBOX_LIST_NAME_FS) == 0 &&
	    *list->set.maildir_name == '\0') {
		/* have to use .imap/ directories */
		list->v.get_path = mbox_list_get_path;
	}
	list->v.iter_is_mailbox = mbox_list_iter_is_mailbox;
	list->v.delete_mailbox = mbox_list_delete_mailbox;
	list->v.is_valid_existing_name = mbox_is_valid_existing_name;
	list->v.is_valid_create_name = mbox_is_valid_create_name;

	MODULE_CONTEXT_SET(list, mbox_mailbox_list_module, mlist);
}

static struct mailbox_transaction_context *
mbox_transaction_begin(struct mailbox *box,
		       enum mailbox_transaction_flags flags)
{
	struct mbox_transaction_context *mt;

	mt = i_new(struct mbox_transaction_context, 1);
	index_transaction_init(&mt->ictx, box, flags);
	return &mt->ictx.mailbox_ctx;
}

static void mbox_transaction_unlock(struct mailbox *box, unsigned int lock_id)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;

	if (lock_id != 0)
		(void)mbox_unlock(mbox, lock_id);
	if (mbox->mbox_global_lock_id == 0) {
		i_assert(mbox->ibox.box.transaction_count > 0 ||
			 mbox->mbox_lock_type == F_UNLCK);
	} else {
		/* mailbox opened with MAILBOX_FLAG_KEEP_LOCKED */
		i_assert(mbox->mbox_lock_type == F_WRLCK);
	}
}

static int
mbox_transaction_commit(struct mailbox_transaction_context *t,
			struct mail_transaction_commit_changes *changes_r)
{
	struct mbox_transaction_context *mt =
		(struct mbox_transaction_context *)t;
	struct mailbox *box = t->box;
	unsigned int lock_id = mt->mbox_lock_id;
	int ret;

	ret = index_transaction_commit(t, changes_r);
	mbox_transaction_unlock(box, lock_id);
	return ret;
}

static void
mbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct mbox_transaction_context *mt =
		(struct mbox_transaction_context *)t;
	struct mailbox *box = t->box;
	unsigned int lock_id = mt->mbox_lock_id;

	index_transaction_rollback(t);
	mbox_transaction_unlock(box, lock_id);
}

struct mail_storage mbox_storage = {
	.name = MBOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_MAILBOX_IS_FILE,

	.v = {
                mbox_get_setting_parser_info,
		mbox_storage_alloc,
		mbox_storage_create,
		NULL,
		mbox_storage_add_list,
		mbox_storage_get_list_settings,
		mbox_storage_autodetect,
		mbox_mailbox_alloc,
		NULL
	}
};

struct mailbox mbox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		mbox_mailbox_open,
		mbox_mailbox_close,
		mbox_mailbox_create,
		mbox_mailbox_update,
		mbox_storage_get_status,
		NULL,
		NULL,
		mbox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		mbox_notify_changes,
		mbox_transaction_begin,
		mbox_transaction_commit,
		mbox_transaction_rollback,
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
		mbox_save_alloc,
		mbox_save_begin,
		mbox_save_continue,
		mbox_save_finish,
		mbox_save_cancel,
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
