/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

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

#define CREATE_MODE 0770 /* umask() should limit it more */

/* How often to touch the dotlock file when using KEEP_LOCKED flag */
#define MBOX_LOCK_TOUCH_MSECS (10*1000)

/* Assume that if atime < mtime, there are new mails. If it's good enough for
   UW-IMAP, it's good enough for us. */
#define STAT_GET_MARKED(st) \
	((st).st_size == 0 ? MAILBOX_UNMARKED : \
	 (st).st_atime < (st).st_mtime ? MAILBOX_MARKED : MAILBOX_UNMARKED)

#define MBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mbox_mailbox_list_module)

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

static int mbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				     const char *dir, const char *fname,
				     const char *mailbox_name,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags);
static int mbox_list_delete_mailbox(struct mailbox_list *list,
				    const char *name);

int mbox_set_syscall_error(struct mbox_mailbox *mbox, const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		mail_storage_set_error(&mbox->storage->storage,
			MAIL_ERROR_NOSPACE, MAIL_ERRSTR_NO_SPACE);
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
					  "%s failed with mbox file %s: %m",
					  function, mbox->path);
	}
	return -1;
}

static bool mbox_is_file(const char *path, const char *name, bool debug)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		if (debug) {
			i_info("mbox autodetect: %s: stat(%s) failed: %m",
			       name, path);
		}
		return FALSE;
	}
	if (S_ISDIR(st.st_mode)) {
		if (debug) {
			i_info("mbox autodetect: %s: is a directory (%s)",
			       name, path);
		}
		return FALSE;
	}
	if (access(path, R_OK|W_OK) < 0) {
		if (debug) {
			i_info("mbox autodetect: %s: no R/W access (%s)",
			       name, path);
		}
		return FALSE;
	}

	if (debug)
		i_info("mbox autodetect: %s: yes (%s)", name, path);
	return TRUE;
}

static bool mbox_is_dir(const char *path, const char *name, bool debug)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		if (debug) {
			i_info("mbox autodetect: %s: stat(%s) failed: %m",
			       name, path);
		}
		return FALSE;
	}
	if (!S_ISDIR(st.st_mode)) {
		if (debug) {
			i_info("mbox autodetect: %s: is not a directory (%s)",
			       name, path);
		}
		return FALSE;
	}
	if (access(path, R_OK|W_OK|X_OK) < 0) {
		if (debug) {
			i_info("mbox autodetect: %s: no R/W/X access (%s)",
			       name, path);
		}
		return FALSE;
	}

	if (debug)
		i_info("mbox autodetect: %s: yes (%s)", name, path);
	return TRUE;
}

static bool mbox_autodetect(const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	const char *path;

	path = t_strcut(data, ':');

	if (debug) {
		if (strchr(data, ':') != NULL) {
			i_info("mbox autodetect: data=%s, splitting ':' -> %s",
			       data, path);
		} else {
			i_info("mbox autodetect: data=%s", data);
		}
	}

	if (*path != '\0' && mbox_is_file(path, "INBOX file", debug))
		return TRUE;

	if (mbox_is_dir(t_strconcat(path, "/"MBOX_INDEX_DIR_NAME, NULL),
			"has "MBOX_INDEX_DIR_NAME"/", debug))
		return TRUE;
	if (mbox_is_file(t_strconcat(path, "/inbox", NULL), "has inbox", debug))
		return TRUE;
	if (mbox_is_file(t_strconcat(path, "/mbox", NULL), "has mbox", debug))
		return TRUE;

	return FALSE;
}

static const char *get_root_dir(struct mail_storage *storage)
{
	const char *home, *path;
	bool debug = (storage->flags & MAIL_STORAGE_FLAG_DEBUG) != 0;

	if (mail_user_get_home(storage->ns->user, &home) > 0) {
		path = t_strconcat(home, "/mail", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_info("mbox: root exists (%s)", path);
			return path;
		}
		if (debug)
			i_info("mbox: root: access(%s, rwx) failed: %m", path);

		path = t_strconcat(home, "/Mail", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_info("mbox: root exists (%s)", path);
			return path;
		}
		if (debug)
			i_info("mbox: root: access(%s, rwx) failed: %m", path);
	}

	if (debug)
		i_info("mbox: checking if we are chrooted:");
	if (mbox_autodetect("", storage->flags))
		return "/";

	if (debug)
		i_info("mbox: root mail directory not found");

	return NULL;
}

static const char *
get_inbox_file(const char *user, const char *root_dir,
	       bool only_root, bool debug)
{
	const char *path;

	if (!only_root) {
		path = t_strconcat("/var/mail/", user, NULL);
		if (access(path, R_OK|W_OK) == 0) {
			if (debug)
				i_info("mbox: INBOX exists (%s)", path);
			return path;
		}
		if (debug)
			i_info("mbox: INBOX: access(%s, rw) failed: %m", path);

		path = t_strconcat("/var/spool/mail/", user, NULL);
		if (access(path, R_OK|W_OK) == 0) {
			if (debug)
				i_info("mbox: INBOX exists (%s)", path);
			return path;
		}
		if (debug)
			i_info("mbox: INBOX: access(%s, rw) failed: %m", path);
	}

	path = t_strconcat(root_dir, "/inbox", NULL);
	if (debug)
		i_info("mbox: INBOX defaulted to %s", path);
	return path;
}

static const char *create_root_dir(struct mail_storage *storage,
				   const char **error_r)
{
	const char *home, *path;

	if (mail_user_get_home(storage->ns->user, &home) <= 0) {
		*error_r = "Root mail directory not set and "
			"home directory is missing";
		return NULL;
	}

	path = t_strconcat(home, "/mail", NULL);
	if (mkdir_parents(path, CREATE_MODE) < 0 && errno != EEXIST) {
		*error_r = mail_error_create_eacces_msg("mkdir", path);
		return NULL;
	}

	if ((storage->flags & MAIL_STORAGE_FLAG_DEBUG) != 0)
		i_info("mbox: root directory created: %s", path);
	return path;
}

static int
mbox_get_list_settings(struct mailbox_list_settings *list_set,
		       const char *data, struct mail_storage *storage,
		       const char **layout_r, const char **error_r)
{
	enum mail_storage_flags flags = storage->flags;
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	const char *p;
	struct stat st;
	bool autodetect;

	*layout_r = "fs";

	memset(list_set, 0, sizeof(*list_set));
	list_set->subscription_fname = MBOX_SUBSCRIPTION_FILE_NAME;
	list_set->maildir_name = "";

	autodetect = data == NULL || *data == '\0';
	if (autodetect) {
		if ((flags & MAIL_STORAGE_FLAG_NO_AUTODETECTION) != 0) {
			*error_r = "Root mail directory not given";
			return -1;
		}

		/* we'll need to figure out the mail location ourself.
		   it's root dir if we've already chroot()ed, otherwise
		   either ~/mail or ~/Mail */
		list_set->root_dir = get_root_dir(storage);
	} else {
		if (debug)
			i_info("mbox: data=%s", data);
		p = strchr(data, ':');
		if ((flags & MAIL_STORAGE_FLAG_NO_AUTODETECTION) == 0 &&
		    p == NULL && data[strlen(data)-1] != '/') {
			/* if the data points to a file, treat it as an INBOX */
			data = mail_user_home_expand(storage->ns->user, data);
			if (stat(data, &st) < 0 || S_ISDIR(st.st_mode))
				list_set->root_dir = data;
			else {
				list_set->root_dir = get_root_dir(storage);
				list_set->inbox_path = data;
			}
		} else if (strncmp(data, "INBOX=", 6) == 0) {
			/* the most common misconfiguration */
			*error_r = "Root mail directory not given";
			return -1;
		} else {
			if (mailbox_list_settings_parse(data, list_set,
							storage->ns,
							layout_r, NULL,
							error_r) < 0)
				return -1;
		}
	}

	if (list_set->root_dir == NULL || *list_set->root_dir == '\0') {
		if ((flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
			*error_r = "Root mail directory not given";
			return -1;
		}

		list_set->root_dir = create_root_dir(storage, error_r);
		if (list_set->root_dir == NULL)
			return -1;
	} else {
		/* make sure the directory exists */
		if (lstat(list_set->root_dir, &st) == 0) {
			/* yep, go ahead */
		} else if (errno == EACCES) {
			*error_r = mail_error_eacces_msg("lstat",
							 list_set->root_dir);
			return -1;
		} else if (errno != ENOENT && errno != ENOTDIR) {
			*error_r = t_strdup_printf("lstat(%s) failed: %m",
						   list_set->root_dir);
			return -1;
		} else if (errno == ENOENT &&
			   storage->ns->type == NAMESPACE_SHARED) {
			/* can't create a new user, but we don't want to fail
			   the storage creation. */
		} else if ((flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
			*error_r = t_strdup_printf(
					"Root mail directory doesn't exist: %s",
					list_set->root_dir);
			return -1;
		} else if (mkdir_parents(list_set->root_dir, CREATE_MODE) < 0 &&
			   errno != EEXIST) {
			*error_r = mail_error_create_eacces_msg("mkdir",
							list_set->root_dir);
			return -1;
		}
	}

	if (list_set->inbox_path == NULL) {
		list_set->inbox_path =
			get_inbox_file(storage->ns->user->username,
				       list_set->root_dir, !autodetect, debug);
	}
	return 0;
}

static const char *
mbox_list_get_path(struct mailbox_list *list, const char *name,
		   enum mailbox_list_path_type type)
{
	struct mbox_storage *storage = MBOX_LIST_CONTEXT(list);
	const char *path, *p;

	path = storage->list_module_ctx.super.get_path(list, name, type);
	if (type == MAILBOX_LIST_PATH_TYPE_CONTROL ||
	    type == MAILBOX_LIST_PATH_TYPE_INDEX) {
		p = strrchr(path, '/');
		if (p == NULL)
			return "";

		return t_strconcat(t_strdup_until(path, p),
				   "/"MBOX_INDEX_DIR_NAME"/", p+1, NULL);
	}
	return path;
}

static struct mail_storage *mbox_alloc(void)
{
	struct mbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("mbox storage", 512+256);
	storage = p_new(pool, struct mbox_storage, 1);
	storage->storage = mbox_storage;
	storage->storage.pool = pool;
	storage->storage.storage_class = &mbox_storage;

	return &storage->storage;
}

static bool mbox_name_is_dotlock(const char *name)
{
	unsigned int len = strlen(name);

	return len >= 5 && strcmp(name + len - 5, ".lock") == 0;
}

static bool
mbox_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	struct mbox_storage *storage = MBOX_LIST_CONTEXT(list);

	return storage->list_module_ctx.super.
		is_valid_existing_name(list, name) &&
		!mbox_name_is_dotlock(name);
}

static bool
mbox_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	struct mbox_storage *storage = MBOX_LIST_CONTEXT(list);

	return storage->list_module_ctx.super.
		is_valid_create_name(list, name) &&
		!mbox_name_is_dotlock(name);
}

static int mbox_create(struct mail_storage *_storage, const char *data,
		       const char **error_r)
{
	struct mbox_storage *storage = (struct mbox_storage *)_storage;
	struct mailbox_list_settings list_set;
	const char *layout;

	if (mbox_get_list_settings(&list_set, data, _storage,
				   &layout, error_r) < 0)
		return -1;
	list_set.mail_storage_flags = &_storage->flags;
	list_set.lock_method = &_storage->lock_method;

	if (mailbox_list_alloc(layout, &_storage->list, error_r) < 0)
		return -1;

	storage->list_module_ctx.super = _storage->list->v;
	if (strcmp(layout, "fs") == 0 && *list_set.maildir_name == '\0') {
		/* have to use .imap/ directories */
		_storage->list->v.get_path = mbox_list_get_path;
	}
	_storage->list->v.iter_is_mailbox = mbox_list_iter_is_mailbox;
	_storage->list->v.delete_mailbox = mbox_list_delete_mailbox;
	_storage->list->v.is_valid_existing_name = mbox_is_valid_existing_name;
	_storage->list->v.is_valid_create_name = mbox_is_valid_create_name;

	MODULE_CONTEXT_SET_FULL(_storage->list, mbox_mailbox_list_module,
				storage, &storage->list_module_ctx);

	/* finish list init after we've overridden vfuncs */
	mailbox_list_init(_storage->list, _storage->ns, &list_set,
			  mail_storage_get_list_flags(_storage->flags) |
			  MAILBOX_LIST_FLAG_MAILBOX_FILES);
	return 0;
}

static int verify_inbox(struct mail_storage *storage)
{
	const char *inbox_path, *rootdir;
	int fd;

	inbox_path = mailbox_list_get_path(storage->list, "INBOX",
					   MAILBOX_LIST_PATH_TYPE_MAILBOX);
	rootdir = mailbox_list_get_path(storage->list, "",
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
		mail_storage_set_critical(storage,
			"mbox root directory can't be a file: %s "
			"(http://wiki.dovecot.org/MailLocation/Mbox)",
			rootdir);
		return -1;
	} else if (errno == EACCES) {
		mail_storage_set_critical(storage, "%s",
			mail_error_create_eacces_msg("open", inbox_path));
		return -1;
	} else if (errno != EEXIST) {
		mail_storage_set_critical(storage,
			"open(%s, O_CREAT) failed: %m", inbox_path);
		return -1;
	}

	return 0;
}

static bool want_memory_indexes(struct mbox_storage *storage, const char *path)
{
	const char *env;
	struct stat st;
	unsigned int min_size;

	env = getenv("MBOX_MIN_INDEX_SIZE");
	if (env == NULL)
		return FALSE;

	min_size = strtoul(env, NULL, 10);
	if (min_size == 0)
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
	return st.st_size / 1024 < min_size;
}

static void mbox_lock_touch_timeout(struct mbox_mailbox *mbox)
{
	mbox_dotlock_touch(mbox);
}

static struct mbox_mailbox *
mbox_alloc_mailbox(struct mbox_storage *storage, struct mail_index *index,
		   const char *name, const char *path,
		   enum mailbox_open_flags flags)
{
	struct mbox_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("mbox mailbox", 1024+512);
	mbox = p_new(pool, struct mbox_mailbox, 1);
	mbox->ibox.box = mbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = &storage->storage;
	mbox->ibox.mail_vfuncs = &mbox_mail_vfuncs;
	mbox->ibox.index = index;

	mbox->storage = storage;
	mbox->path = p_strdup(mbox->ibox.box.pool, path);
	mbox->mbox_fd = -1;
	mbox->mbox_lock_type = F_UNLCK;
	mbox->mbox_ext_idx =
		mail_index_ext_register(index, "mbox",
					sizeof(mbox->mbox_hdr),
					sizeof(uint64_t), sizeof(uint64_t));

        mbox->mbox_very_dirty_syncs = getenv("MBOX_VERY_DIRTY_SYNCS") != NULL;
	mbox->mbox_do_dirty_syncs = mbox->mbox_very_dirty_syncs ||
		getenv("MBOX_DIRTY_SYNCS") != NULL;

	if ((storage->storage.flags & MAIL_STORAGE_FLAG_KEEP_HEADER_MD5) != 0)
		mbox->mbox_save_md5 = TRUE;

	index_storage_mailbox_init(&mbox->ibox, name, flags,
				   want_memory_indexes(storage, path));

	if ((flags & MAILBOX_OPEN_KEEP_LOCKED) != 0) {
		if (mbox_lock(mbox, F_WRLCK, &mbox->mbox_global_lock_id) <= 0) {
			struct mailbox *box = &mbox->ibox.box;

			mailbox_close(&box);
			return NULL;
		}

		if (mbox->mbox_dotlock != NULL) {
			mbox->keep_lock_to =
				timeout_add(MBOX_LOCK_TOUCH_MSECS,
					    mbox_lock_touch_timeout, mbox);
		}
	}

	return mbox;
}

static struct mailbox *
mbox_open(struct mbox_storage *storage, const char *name,
	  enum mailbox_open_flags flags)
{
	struct mail_storage *_storage = &storage->storage;
	struct mbox_mailbox *mbox;
	struct mail_index *index;
	const char *path, *rootdir;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	index = index_storage_alloc(_storage, name, flags, MBOX_INDEX_PREFIX);
	mbox = mbox_alloc_mailbox(storage, index, name, path, flags);

	if (access(path, R_OK|W_OK) < 0) {
		if (errno < EACCES)
			mbox_set_syscall_error(mbox, "access()");
		else
			mbox->ibox.backend_readonly = TRUE;
	}

	if (strcmp(name, "INBOX") == 0) {
		/* if INBOX isn't under the root directory, it's probably in
		   /var/mail and we want to allow privileged dotlocking */
		rootdir = mailbox_list_get_path(_storage->list, NULL,
						MAILBOX_LIST_PATH_TYPE_DIR);
		if (strncmp(path, rootdir, strlen(rootdir)) != 0)
			mbox->mbox_privileged_locking = TRUE;
	}
	return &mbox->ibox.box;
}

static struct mailbox *
mbox_mailbox_open_stream(struct mbox_storage *storage, const char *name,
			 struct istream *input, enum mailbox_open_flags flags)
{
	struct mail_storage *_storage = &storage->storage;
	struct mail_index *index;
	struct mbox_mailbox *mbox;
	const char *path;

	flags |= MAILBOX_OPEN_READONLY;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index = index_storage_alloc(_storage, name, flags, MBOX_INDEX_PREFIX);
	mbox = mbox_alloc_mailbox(storage, index, name, path, flags);
	if (mbox == NULL)
		return NULL;

	i_stream_ref(input);
	mbox->mbox_file_stream = input;
	mbox->ibox.backend_readonly = TRUE;
	mbox->no_mbox_file = TRUE;

	mbox->path = "(read-only mbox stream)";
	return &mbox->ibox.box;
}

static struct mailbox *
mbox_mailbox_open(struct mail_storage *_storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	struct mbox_storage *storage = (struct mbox_storage *)_storage;
	const char *path;
	struct stat st;

	if (input != NULL)
		return mbox_mailbox_open_stream(storage, name, input, flags);

	if (strcmp(name, "INBOX") == 0 &&
	    (_storage->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		/* make sure INBOX exists */
		if (verify_inbox(_storage) < 0)
			return NULL;
		return mbox_open(storage, "INBOX", flags);
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			mail_storage_set_error(_storage, MAIL_ERROR_NOTPOSSIBLE,
				t_strdup_printf("Mailbox isn't selectable: %s",
						name));
			return NULL;
		}

		return mbox_open(storage, name, flags);
	}

	if (ENOTFOUND(errno)) {
		mail_storage_set_error(_storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
	} else if (!mail_storage_set_error_from_errno(_storage)) {
		mail_storage_set_critical(_storage, "stat(%s) failed: %m",
					  path);
	}

	return NULL;
}

static int mbox_mailbox_create(struct mail_storage *_storage, const char *name,
			       bool directory)
{
	const char *path, *p;
	struct stat st;
	mode_t mode;
	gid_t gid;
	int fd;

	/* make sure it doesn't exist already */
	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(_storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}

	if (errno != ENOENT) {
		if (errno == ENOTDIR) {
			mail_storage_set_error(_storage, MAIL_ERROR_NOTPOSSIBLE,
				"Mailbox doesn't allow inferior mailboxes");
		} else if (!mail_storage_set_error_from_errno(_storage)) {
			mail_storage_set_critical(_storage,
				"stat() failed for mbox file %s: %m", path);
		}
		return -1;
	}

	/* create the hierarchy if needed */
	p = directory ? path + strlen(path) : strrchr(path, '/');
	if (p != NULL) {
		p = t_strdup_until(path, p);
		mailbox_list_get_dir_permissions(_storage->list, &mode, &gid);
		if (mkdir_parents_chown(p, mode, (uid_t)-1, gid) < 0 &&
		    errno != EEXIST) {
			if (!mail_storage_set_error_from_errno(_storage)) {
				mail_storage_set_critical(_storage,
					"mkdir_parents(%s) failed: %m", p);
			}
			return -1;
		}

		if (directory) {
			/* wanted to create only the directory */
			return 0;
		}
	}

	/* create the mailbox file */
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd != -1) {
		(void)close(fd);
		return 0;
	}

	if (errno == EEXIST) {
		/* mailbox was just created between stat() and open() call.. */
		mail_storage_set_error(_storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
	} else if (!mail_storage_set_error_from_errno(_storage)) {
		mail_storage_set_critical(_storage,
			"Can't create mailbox %s: %m", name);
	}
	return -1;
}

static int mbox_storage_mailbox_close(struct mailbox *box)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;
	const struct mail_index_header *hdr;
	enum mbox_sync_flags sync_flags = 0;
	int ret = 0;

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
	if (sync_flags != 0 && !mbox->invalid_mbox_file) {
		if (mbox_sync(mbox, sync_flags) < 0)
			ret = -1;
	}

	if (mbox->mbox_global_lock_id != 0)
		(void)mbox_unlock(mbox, mbox->mbox_global_lock_id);
	if (mbox->keep_lock_to != NULL)
		timeout_remove(&mbox->keep_lock_to);

        mbox_file_close(mbox);
	if (mbox->mbox_file_stream != NULL)
		i_stream_destroy(&mbox->mbox_file_stream);

	return index_storage_mailbox_close(box) < 0 ? -1 : ret;
}

static void mbox_notify_changes(struct mailbox *box)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)box;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->ibox);
	else if (!mbox->no_mbox_file)
		index_mailbox_check_add(&mbox->ibox, mbox->path);
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

static int mbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				     const char *dir, const char *fname,
				     const char *mailbox_name ATTR_UNUSED,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags)
{
	struct mail_storage *storage = MBOX_LIST_CONTEXT(ctx->list);
	const char *path, *root_dir;
	size_t len;
	struct stat st;

	if (strcmp(fname, MBOX_INDEX_DIR_NAME) == 0) {
		*flags |= MAILBOX_NOSELECT;
		return 0;
	}
	if (strcmp(fname, MBOX_SUBSCRIPTION_FILE_NAME) == 0) {
		root_dir = mailbox_list_get_path(storage->list, NULL,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
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
	struct mbox_storage *storage = MBOX_LIST_CONTEXT(list);
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
	index_storage_destroy_unrefed();
	if (storage->list_module_ctx.super.delete_mailbox(list, name) < 0)
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

static void mbox_class_init(void)
{
	mbox_transaction_class_init();
}

static void mbox_class_deinit(void)
{
	mbox_transaction_class_deinit();
}

struct mail_storage mbox_storage = {
	MEMBER(name) MBOX_STORAGE_NAME,
	MEMBER(mailbox_is_file) TRUE,

	{
		mbox_class_init,
		mbox_class_deinit,
		mbox_alloc,
		mbox_create,
		index_storage_destroy,
		mbox_autodetect,
		mbox_mailbox_open,
		mbox_mailbox_create
	}
};

struct mailbox mbox_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		mbox_storage_mailbox_close,
		index_storage_get_status,
		NULL,
		NULL,
		mbox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		mbox_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		index_transaction_set_max_modseq,
		index_keywords_create,
		index_keywords_free,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunged_uids,
		NULL,
		NULL,
		NULL,
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_ref,
		index_header_lookup_unref,
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
