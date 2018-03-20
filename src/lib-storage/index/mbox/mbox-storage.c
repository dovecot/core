/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "restrict-access.h"
#include "master-service.h"
#include "mailbox-list-private.h"
#include "mbox-storage.h"
#include "mbox-lock.h"
#include "mbox-file.h"
#include "mbox-sync-private.h"
#include "istream-raw-mbox.h"
#include "mail-copy.h"
#include "index-mail.h"

#include <sys/stat.h>

/* How often to touch the dotlock file when using KEEP_LOCKED flag */
#define MBOX_LOCK_TOUCH_MSECS (10*1000)

/* Assume that if atime < mtime, there are new mails. If it's good enough for
   UW-IMAP, it's good enough for us. */
#define STAT_GET_MARKED(st) \
	((st).st_size == 0 ? MAILBOX_UNMARKED : \
	 (st).st_atime < (st).st_mtime ? MAILBOX_MARKED : MAILBOX_UNMARKED)

#define MBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mbox_mailbox_list_module)

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
	"X-Delivery-ID",
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

void mbox_set_syscall_error(struct mbox_mailbox *mbox, const char *function)
{
	i_assert(function != NULL);

	if (ENOQUOTA(errno)) {
		mail_storage_set_error(&mbox->storage->storage,
			MAIL_ERROR_NOQUOTA, MAIL_ERRSTR_NO_QUOTA);
	} else {
		const char *toobig_error = errno != EFBIG ? "" :
			" (process was started with ulimit -f limit)";
		mailbox_set_critical(&mbox->box,
			"%s failed with mbox: %m%s", function, toobig_error);
	}
}

static int
mbox_list_get_path(struct mailbox_list *list, const char *name,
		   enum mailbox_list_path_type type, const char **path_r)
{
	struct mbox_mailbox_list *mlist = MBOX_LIST_CONTEXT(list);
	const char *path, *p;
	int ret;

	*path_r = NULL;

	ret = mlist->module_ctx.super.get_path(list, name, type, &path);
	if (ret <= 0)
		return ret;

	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_CONTROL:
	case MAILBOX_LIST_PATH_TYPE_INDEX:
	case MAILBOX_LIST_PATH_TYPE_INDEX_CACHE:
	case MAILBOX_LIST_PATH_TYPE_LIST_INDEX:
		if (name == NULL && type == MAILBOX_LIST_PATH_TYPE_CONTROL &&
		    list->set.control_dir != NULL) {
			/* kind of a kludge for backwards compatibility:
			   the subscriptions file is in the root control_dir
			   without .imap/ suffix */
			*path_r = path;
			return 1;
		}
		if (name == NULL) {
			*path_r = t_strconcat(path, "/"MBOX_INDEX_DIR_NAME, NULL);
			return 1;
		}

		p = strrchr(path, '/');
		if (p == NULL)
			return 0;

		*path_r = t_strconcat(t_strdup_until(path, p),
				      "/"MBOX_INDEX_DIR_NAME"/", p+1, NULL);
		break;
	case MAILBOX_LIST_PATH_TYPE_DIR:
	case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
	case MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE:
		*path_r = path;
		break;
	}
	return 1;
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
		    const char **error_r)
{
	struct mbox_storage *storage = MBOX_STORAGE(_storage);
	struct stat st;
	const char *dir;

	if (master_service_get_client_limit(master_service) > 1) {
		/* we can't handle locking related problems. */
		*error_r = "mbox requires client_limit=1 for service";
		return -1;
	}

	storage->set = mail_namespace_get_driver_settings(ns, _storage);

	if (mailbox_list_get_root_path(ns->list, MAILBOX_LIST_PATH_TYPE_INDEX, &dir)) {
		_storage->temp_path_prefix = p_strconcat(_storage->pool, dir,
			"/", mailbox_list_get_temp_prefix(ns->list), NULL);
	}
	if (stat(ns->list->set.root_dir, &st) == 0 && !S_ISDIR(st.st_mode)) {
		*error_r = t_strdup_printf(
			"mbox root directory can't be a file: %s "
			"(http://wiki2.dovecot.org/MailLocation/Mbox)",
			ns->list->set.root_dir);
		return -1;
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
		e_debug(ns->user->event, "mbox: INBOX defaulted to %s", set->inbox_path);
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

	if (ns->owner == NULL ||
	    mail_user_get_home(ns->owner, &home) <= 0) {
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
		   const char *vname, enum mailbox_flags flags)
{
	struct mbox_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("mbox mailbox", 1024*3);
	mbox = p_new(pool, struct mbox_mailbox, 1);
	mbox->box = mbox_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &mbox_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = MBOX_STORAGE(storage);
	mbox->mbox_fd = -1;
	mbox->mbox_lock_type = F_UNLCK;
	mbox->mbox_list_index_ext_id = (uint32_t)-1;

	if (strcmp(mbox->storage->set->mbox_md5, "apop3d") == 0)
		mbox->md5_v = mbox_md5_apop3d;
	else if (strcmp(mbox->storage->set->mbox_md5, "all") == 0)
		mbox->md5_v = mbox_md5_all;
	else {
		i_fatal("Invalid mbox_md5 setting: %s",
			mbox->storage->set->mbox_md5);
	}

	if ((storage->flags & MAIL_STORAGE_FLAG_KEEP_HEADER_MD5) != 0)
		mbox->mbox_save_md5 = TRUE;
	return &mbox->box;
}

static void mbox_lock_touch_timeout(struct mbox_mailbox *mbox)
{
	mbox_dotlock_touch(mbox);
}

static int
mbox_mailbox_open_finish(struct mbox_mailbox *mbox, bool move_to_memory)
{
	if (index_storage_mailbox_open(&mbox->box, move_to_memory) < 0)
		return -1;

	mbox->mbox_ext_idx =
		mail_index_ext_register(mbox->box.index, "mbox",
					sizeof(mbox->mbox_hdr),
					sizeof(uint64_t), sizeof(uint64_t));
	mbox->md5hdr_ext_idx =
		mail_index_ext_register(mbox->box.index, "header-md5",
					0, 16, 1);
	return 0;
}

static int mbox_mailbox_open_existing(struct mbox_mailbox *mbox)
{
	struct mailbox *box = &mbox->box;
	const char *rootdir, *box_path = mailbox_get_path(box);
	bool move_to_memory;

	move_to_memory = want_memory_indexes(mbox->storage, box_path);

	if (box->inbox_any || strcmp(box->name, "INBOX") == 0) {
		/* if INBOX isn't under the root directory, it's probably in
		   /var/mail and we want to allow privileged dotlocking */
		rootdir = mailbox_list_get_root_forced(box->list,
						       MAILBOX_LIST_PATH_TYPE_DIR);
		if (!str_begins(box_path, rootdir))
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
	return mbox_mailbox_open_finish(mbox, move_to_memory);
}

static bool mbox_storage_is_readonly(struct mailbox *box)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);

	if (index_storage_is_readonly(box))
		return TRUE;

	if (mbox_is_backend_readonly(mbox)) {
		/* return read-only only if there are no private flags
		   (that are stored in index files) */
		if (mailbox_get_private_flags_mask(box) == 0)
			return TRUE;
	}
	return FALSE;
}

static int mbox_mailbox_open(struct mailbox *box)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	struct stat st;
	int ret;

	if (box->input != NULL) {
		i_stream_ref(box->input);
		mbox->mbox_file_stream = box->input;
		mbox->backend_readonly = TRUE;
		mbox->backend_readonly_set = TRUE;
		mbox->no_mbox_file = TRUE;
		return mbox_mailbox_open_finish(mbox, FALSE);
	}

	ret = stat(mailbox_get_path(box), &st);
	if (ret == 0) {
		if (!S_ISDIR(st.st_mode))
			return mbox_mailbox_open_existing(mbox);
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				       "Mailbox isn't selectable");
		return -1;
	} else if (ENOTFOUND(errno)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	} else if (mail_storage_set_error_from_errno(box->storage)) {
		return -1;
	} else {
		mailbox_set_critical(box,
			"stat(%s) failed: %m", mailbox_get_path(box));
		return -1;
	}
}

static int
mbox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}

	if (update->uid_validity != 0 || update->min_next_uid != 0 ||
	    !guid_128_is_empty(update->mailbox_guid)) {
		mbox->sync_hdr_update = update;
		ret = mbox_sync(mbox, MBOX_SYNC_HEADER | MBOX_SYNC_FORCE_SYNC |
				MBOX_SYNC_REWRITE);
		mbox->sync_hdr_update = NULL;
	}
	if (ret == 0)
		ret = index_storage_mailbox_update(box, update);
	return ret;
}

static int create_inbox(struct mailbox *box)
{
	const char *inbox_path;
	int fd;

	inbox_path = mailbox_get_path(box);

	fd = open(inbox_path, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd == -1 && errno == EACCES) {
		/* try again with increased privileges */
		(void)restrict_access_use_priv_gid();
		fd = open(inbox_path, O_RDWR | O_CREAT | O_EXCL, 0660);
		restrict_access_drop_priv_gid();
	}
	if (fd != -1) {
		i_close_fd(&fd);
		return 0;
	} else if (errno == EACCES) {
		mailbox_set_critical(box, "%s",
			mail_error_create_eacces_msg("open", inbox_path));
		return -1;
	} else if (errno == EEXIST) {
		mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	} else {
		mailbox_set_critical(box,
			"open(%s, O_CREAT) failed: %m", inbox_path);
		return -1;
	}
}

static int
mbox_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		    bool directory)
{
	int fd, ret;

	if ((ret = index_storage_mailbox_create(box, directory)) <= 0)
		return ret;

	if (box->inbox_any) {
		if (create_inbox(box) < 0)
			return -1;
	} else {
		/* create the mbox file */
		ret = mailbox_create_fd(box, mailbox_get_path(box),
					O_RDWR | O_CREAT | O_EXCL, &fd);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
					       "Mailbox already exists");
			return -1;
		}
		i_close_fd(&fd);
	}
	return update == NULL ? 0 : mbox_mailbox_update(box, update);
}

static void mbox_mailbox_close(struct mailbox *box)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	const struct mail_index_header *hdr;
	enum mbox_sync_flags sync_flags = 0;

	if (mbox->mbox_stream != NULL &&
	    istream_raw_mbox_is_corrupted(mbox->mbox_stream)) {
		/* clear the corruption by forcing a full resync */
		sync_flags |= MBOX_SYNC_UNDIRTY | MBOX_SYNC_FORCE_SYNC;
	}

	if (box->view != NULL) {
		hdr = mail_index_get_header(box->view);
		if ((hdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0 &&
		    !mbox_is_backend_readonly(mbox)) {
			/* we've done changes to mbox which haven't been
			   written yet. do it now. */
			sync_flags |= MBOX_SYNC_REWRITE;
		}
	}
	if (sync_flags != 0 && !mbox->invalid_mbox_file)
		(void)mbox_sync(mbox, sync_flags);

	if (mbox->mbox_global_lock_id != 0)
		mbox_unlock(mbox, mbox->mbox_global_lock_id);
	timeout_remove(&mbox->keep_lock_to);

        mbox_file_close(mbox);
	i_stream_destroy(&mbox->mbox_file_stream);

	index_storage_mailbox_close(box);
}

static int
mbox_mailbox_get_guid(struct mbox_mailbox *mbox, guid_128_t guid_r)
{
	const char *errstr;

	if (mail_index_is_in_memory(mbox->box.index)) {
		errstr = "Mailbox GUIDs are not permanent without index files";
		if (mbox->storage->set->mbox_min_index_size != 0) {
			errstr = t_strconcat(errstr,
				" (mbox_min_index_size is non-zero)", NULL);
		}
		mail_storage_set_error(mbox->box.storage,
				       MAIL_ERROR_NOTPOSSIBLE, errstr);
		return -1;
	}
	if (mbox_sync_header_refresh(mbox) < 0)
		return -1;

	if (!guid_128_is_empty(mbox->mbox_hdr.mailbox_guid)) {
		/* we have the GUID */
	} else if (mbox_file_open(mbox) < 0)
		return -1;
	else if (mbox->backend_readonly) {
		mail_storage_set_error(mbox->box.storage, MAIL_ERROR_PERM,
			"Can't set mailbox GUID to a read-only mailbox");
		return -1;
	} else {
		/* create another mailbox and sync  */
		struct mailbox *box2;
		struct mbox_mailbox *mbox2;
		int ret;

		i_assert(mbox->mbox_lock_type == F_UNLCK);
		box2 = mailbox_alloc(mbox->box.list, mbox->box.vname, 0);
		ret = mailbox_sync(box2, 0);
		mbox2 = MBOX_MAILBOX(box2);
		memcpy(guid_r, mbox2->mbox_hdr.mailbox_guid, GUID_128_SIZE);
		mailbox_free(&box2);
		return ret;
	}
	memcpy(guid_r, mbox->mbox_hdr.mailbox_guid, GUID_128_SIZE);
	return 0;
}

static int
mbox_mailbox_get_metadata(struct mailbox *box,
			  enum mailbox_metadata_items items,
			  struct mailbox_metadata *metadata_r)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);

	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		if (mbox_mailbox_get_guid(mbox, metadata_r->guid) < 0)
			return -1;
	}
	return 0;
}

static void mbox_notify_changes(struct mailbox *box)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);

	if (box->notify_callback == NULL)
		mailbox_watch_remove_all(box);
	else if (!mbox->no_mbox_file)
		mailbox_watch_add(box, mailbox_get_path(box));
}

static bool
mbox_is_internal_name(struct mailbox_list *list ATTR_UNUSED,
		      const char *name)
{
	size_t len;

	/* don't allow *.lock files/dirs */
	len = strlen(name);
	if (len > 5 && strcmp(name+len-5, ".lock") == 0)
		return TRUE;

	return strcmp(name, MBOX_INDEX_DIR_NAME) == 0;
}

static void mbox_storage_add_list(struct mail_storage *storage,
				  struct mailbox_list *list)
{
	struct mbox_mailbox_list *mlist;

	mlist = p_new(list->pool, struct mbox_mailbox_list, 1);
	mlist->module_ctx.super = list->v;
	mlist->set = mail_namespace_get_driver_settings(list->ns, storage);

	if (strcmp(list->name, MAILBOX_LIST_NAME_FS) == 0 &&
	    *list->set.maildir_name == '\0') {
		/* have to use .imap/ directories */
		list->v.get_path = mbox_list_get_path;
	}
	list->v.is_internal_name = mbox_is_internal_name;

	MODULE_CONTEXT_SET(list, mbox_mailbox_list_module, mlist);
}

static struct mailbox_transaction_context *
mbox_transaction_begin(struct mailbox *box,
		       enum mailbox_transaction_flags flags,
		       const char *reason)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	struct mbox_transaction_context *mt;

	if ((flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0)
		mbox->external_transactions++;

	mt = i_new(struct mbox_transaction_context, 1);
	index_transaction_init(&mt->t, box, flags, reason);
	return &mt->t;
}

static void
mbox_transaction_unlock(struct mailbox *box, unsigned int lock_id1,
			unsigned int lock_id2)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);

	if (lock_id1 != 0)
		mbox_unlock(mbox, lock_id1);
	if (lock_id2 != 0)
		mbox_unlock(mbox, lock_id2);
	if (mbox->mbox_global_lock_id == 0) {
		i_assert(mbox->box.transaction_count > 0);
		i_assert(mbox->box.transaction_count > 1 ||
			 mbox->external_transactions > 0 ||
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
	struct mbox_transaction_context *mt = MBOX_TRANSCTX(t);
	struct mailbox *box = t->box;
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	unsigned int read_lock_id = mt->read_lock_id;
	unsigned int write_lock_id = mt->write_lock_id;
	int ret;

	if ((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0) {
		i_assert(mbox->external_transactions > 0);
		mbox->external_transactions--;
	}

	ret = index_transaction_commit(t, changes_r);
	mbox_transaction_unlock(box, read_lock_id, write_lock_id);
	return ret;
}

static void
mbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct mbox_transaction_context *mt = MBOX_TRANSCTX(t);
	struct mailbox *box = t->box;
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	unsigned int read_lock_id = mt->read_lock_id;
	unsigned int write_lock_id = mt->write_lock_id;

	if ((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0) {
		i_assert(mbox->external_transactions > 0);
		mbox->external_transactions--;
	}

	index_transaction_rollback(t);
	mbox_transaction_unlock(box, read_lock_id, write_lock_id);
}

bool mbox_is_backend_readonly(struct mbox_mailbox *mbox)
{
	if (!mbox->backend_readonly_set) {
		mbox->backend_readonly_set = TRUE;
		if (access(mailbox_get_path(&mbox->box), R_OK|W_OK) < 0 &&
		    errno == EACCES)
			mbox->backend_readonly = TRUE;
	}
	return mbox->backend_readonly;
}

struct mail_storage mbox_storage = {
	.name = MBOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_MAILBOX_IS_FILE |
		MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS,

	.v = {
                mbox_get_setting_parser_info,
		mbox_storage_alloc,
		mbox_storage_create,
		index_storage_destroy,
		mbox_storage_add_list,
		mbox_storage_get_list_settings,
		mbox_storage_autodetect,
		mbox_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox mbox_mailbox = {
	.v = {
		mbox_storage_is_readonly,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		mbox_mailbox_open,
		mbox_mailbox_close,
		index_storage_mailbox_free,
		mbox_mailbox_create,
		mbox_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		mbox_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		mbox_list_index_has_changed,
		mbox_list_index_update_sync,
		mbox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		mbox_notify_changes,
		mbox_transaction_begin,
		mbox_transaction_commit,
		mbox_transaction_rollback,
		NULL,
		index_mail_alloc,
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
		mbox_transaction_save_commit_pre,
		mbox_transaction_save_commit_post,
		mbox_transaction_save_rollback,
		index_storage_is_inconsistent
	}
};
