#ifndef MAILBOX_LIST_H
#define MAILBOX_LIST_H

#include "mail-error.h"

#ifdef PATH_MAX
#  define MAILBOX_LIST_NAME_MAX_LENGTH PATH_MAX
#else
#  define MAILBOX_LIST_NAME_MAX_LENGTH 4096
#endif

struct fs;
struct mail_namespace;
struct mail_storage;
struct mailbox_list;

enum mailbox_list_properties {
	/* maildir_name must always be empty */
	MAILBOX_LIST_PROP_NO_MAILDIR_NAME	= 0x01,
	/* alt directories not supported */
	MAILBOX_LIST_PROP_NO_ALT_DIR		= 0x02,
	/* no support for \noselect directories, only mailboxes */
	MAILBOX_LIST_PROP_NO_NOSELECT		= 0x04,
	/* mail root directory isn't required */
	MAILBOX_LIST_PROP_NO_ROOT		= 0x08,
	/* Automatically create mailbox directories when needed. Normally it's
	   assumed that if a mailbox directory doesn't exist, the mailbox
	   doesn't exist either. */
	MAILBOX_LIST_PROP_AUTOCREATE_DIRS	= 0x10,
	/* Explicitly disable mailbox list index */
	MAILBOX_LIST_PROP_NO_LIST_INDEX		= 0x20,
};

enum mailbox_list_flags {
	/* Mailboxes are files, not directories. */
	MAILBOX_LIST_FLAG_MAILBOX_FILES		= 0x01,
	/* Namespace already has a mailbox list, don't assign this
	   mailbox list to it. */
	MAILBOX_LIST_FLAG_SECONDARY		= 0x02,
	/* There are no mail files, only index and/or control files. */
	MAILBOX_LIST_FLAG_NO_MAIL_FILES		= 0x04,
	/* LAYOUT=index: Don't delete any files in delete_mailbox(). */
	MAILBOX_LIST_FLAG_NO_DELETES		= 0x08
};

enum mailbox_info_flags {
	MAILBOX_NOSELECT		= 0x001,
	MAILBOX_NONEXISTENT		= 0x002,
	MAILBOX_CHILDREN		= 0x004,
	MAILBOX_NOCHILDREN		= 0x008,
	MAILBOX_NOINFERIORS		= 0x010,
	MAILBOX_MARKED			= 0x020,
	MAILBOX_UNMARKED		= 0x040,
	MAILBOX_SUBSCRIBED		= 0x080,
	MAILBOX_CHILD_SUBSCRIBED	= 0x100,
	MAILBOX_CHILD_SPECIALUSE	= 0x200,

	/* Internally used by lib-storage, use mailbox_info.special_use
	   to actually access these: */
	MAILBOX_SPECIALUSE_ALL		= 0x00010000,
	MAILBOX_SPECIALUSE_ARCHIVE	= 0x00020000,
	MAILBOX_SPECIALUSE_DRAFTS	= 0x00040000,
	MAILBOX_SPECIALUSE_FLAGGED	= 0x00080000,
	MAILBOX_SPECIALUSE_JUNK		= 0x00100000,
	MAILBOX_SPECIALUSE_SENT		= 0x00200000,
	MAILBOX_SPECIALUSE_TRASH	= 0x00400000,
	MAILBOX_SPECIALUSE_IMPORTANT	= 0x00800000,
#define MAILBOX_SPECIALUSE_MASK		  0x00ff0000

	/* Internally used by lib-storage: */
	MAILBOX_SELECT			= 0x20000000,
	MAILBOX_MATCHED			= 0x40000000
};

enum mailbox_list_path_type {
	/* Return directory's path (eg. ~/dbox/INBOX) */
	MAILBOX_LIST_PATH_TYPE_DIR,
	MAILBOX_LIST_PATH_TYPE_ALT_DIR,
	/* Return mailbox path (eg. ~/dbox/INBOX/dbox-Mails) */
	MAILBOX_LIST_PATH_TYPE_MAILBOX,
	MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX,
	/* Return control directory */
	MAILBOX_LIST_PATH_TYPE_CONTROL,
	/* Return index directory ("" for in-memory) */
	MAILBOX_LIST_PATH_TYPE_INDEX,
	/* Return the private index directory (NULL if none) */
	MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE,
	/* Return the index cache directory (usually same as
	   MAILBOX_LIST_PATH_TYPE_INDEX) */
	MAILBOX_LIST_PATH_TYPE_INDEX_CACHE,
	/* Return mailbox list index directory (usually same as
	   MAILBOX_LIST_PATH_TYPE_INDEX) */
	MAILBOX_LIST_PATH_TYPE_LIST_INDEX,
};

enum mailbox_list_file_type {
	MAILBOX_LIST_FILE_TYPE_UNKNOWN = 0,
	MAILBOX_LIST_FILE_TYPE_FILE,
	MAILBOX_LIST_FILE_TYPE_DIR,
	MAILBOX_LIST_FILE_TYPE_SYMLINK,
	MAILBOX_LIST_FILE_TYPE_OTHER
};

struct mailbox_list_settings {
	const char *layout; /* FIXME: shouldn't be here */
	const char *root_dir;
	const char *index_dir;
	const char *index_pvt_dir;
	const char *index_cache_dir;
	const char *control_dir;
	const char *alt_dir; /* FIXME: dbox-specific.. */
	/* Backend-local directory where volatile data, such as lock files,
	   can be temporarily created. This setting allows specifying a
	   separate directory for them to reduce disk I/O on the real storage.
	   The volatile_dir can point to an in-memory filesystem. */
	const char *volatile_dir;

	const char *inbox_path;
	const char *subscription_fname;
	const char *list_index_fname;
	/* Mailbox list index directory. NULL defaults to index directory.
	   The path may be relative to the index directory. */
	const char *list_index_dir;
	/* If non-empty, it means that mails exist in a maildir_name
	   subdirectory. eg. if you have a directory containing directories:

	   mail/
	   mail/foo/
	   mail/foo/Maildir

	   If mailbox_name is empty, you have mailboxes "mail", "mail/foo" and
	   "mail/foo/Maildir".

	   If mailbox_name is "Maildir", you have a non-selectable mailbox
	   "mail" and a selectable mailbox "mail/foo". */
	const char *maildir_name;
	/* if set, store mailboxes under root_dir/mailbox_dir_name/.
	   this setting contains either "" or "dir/". */
	const char *mailbox_dir_name;

	/* Encode "bad" characters in mailbox names as <escape_char><hex> */
	char escape_char;
	/* If mailbox name can't be changed reversibly to UTF-8 and back,
	   encode the problematic parts using <broken_char><hex> in the
	   user-visible UTF-8 name. The broken_char itself also has to be
	   encoded the same way. */
	char broken_char;
	/* Use UTF-8 mailbox names on filesystem instead of mUTF-7 */
	bool utf8;
	/* Don't check/create the alt-dir symlink. */
	bool alt_dir_nocheck;
	/* Use maildir_name also for index/control directories. This should
	   have been the default since the beginning, but for backwards
	   compatibility it had to be made an option. */
	bool index_control_use_maildir_name;
	/* Perform mailbox iteration using the index directory instead of the
	   mail root directory. This can be helpful if the indexes are on a
	   faster storage. This could perhaps be made the default at some point,
	   but for now since it's less tested it's optional. */
	bool iter_from_index_dir;
	/* Avoid creating or listing \NoSelect mailboxes. */
	bool no_noselect;
	/* Do not validate names as fs names (allows weird names) */
	bool no_fs_validation;
};

struct mailbox_permissions {
	/* The actual uid/gid of the mailbox */
	uid_t file_uid;
	gid_t file_gid;

	/* mode and GID to use for newly created files/dirs.
	   (gid_t)-1 is used if the default GID can be used. */
	mode_t file_create_mode, dir_create_mode;
	gid_t file_create_gid;
	/* origin (e.g. path) where the file_create_gid was got from */
	const char *file_create_gid_origin;

	bool gid_origin_is_mailbox_path;
	bool mail_index_permissions_set;
};

/* register all drivers */
void mailbox_list_register_all(void);

void mailbox_list_register(const struct mailbox_list *list);
void mailbox_list_unregister(const struct mailbox_list *list);

const struct mailbox_list *
mailbox_list_find_class(const char *driver);

/* Returns 0 if ok, -1 if driver was unknown. */
int mailbox_list_create(const char *driver, struct mail_namespace *ns,
			const struct mailbox_list_settings *set,
			enum mailbox_list_flags flags,
			struct mailbox_list **list_r, const char **error_r);
void mailbox_list_destroy(struct mailbox_list **list);

const char *
mailbox_list_get_driver_name(const struct mailbox_list *list) ATTR_PURE;
const struct mailbox_list_settings *
mailbox_list_get_settings(const struct mailbox_list *list) ATTR_PURE;
enum mailbox_list_flags
mailbox_list_get_flags(const struct mailbox_list *list) ATTR_PURE;
struct mail_namespace *
mailbox_list_get_namespace(const struct mailbox_list *list) ATTR_PURE;
struct mail_user *
mailbox_list_get_user(const struct mailbox_list *list) ATTR_PURE;
int mailbox_list_get_storage(struct mailbox_list **list, const char *vname,
			     struct mail_storage **storage_r);
void mailbox_list_get_default_storage(struct mailbox_list *list,
				      struct mail_storage **storage);
char mailbox_list_get_hierarchy_sep(struct mailbox_list *list);

/* Returns the mode and GID that should be used when creating new files and
   directories to the specified mailbox. (gid_t)-1 is returned if it's not
   necessary to change the default gid. */
void mailbox_list_get_permissions(struct mailbox_list *list, const char *name,
				  struct mailbox_permissions *permissions_r);
/* Like mailbox_list_get_permissions(), but for creating files/dirs to the
   mail root directory (or even the root dir itself). */
void mailbox_list_get_root_permissions(struct mailbox_list *list,
				       struct mailbox_permissions *permissions_r);
/* mkdir() a root directory of given type with proper permissions. The path can
   be either the root itself or point to a directory under the root. */
int mailbox_list_mkdir_root(struct mailbox_list *list, const char *path,
			    enum mailbox_list_path_type type);
/* Like mailbox_list_mkdir_root(), but don't log an error if it fails. */
int mailbox_list_try_mkdir_root(struct mailbox_list *list, const char *path,
				enum mailbox_list_path_type type,
				const char **error_r);
/* Call mailbox_list_mkdir_root() for index, unless the index root is the
   same as mailbox root. Returns 1 if ok, 0 if there are no indexes, -1 if
   error. Calling this multiple times does the check only once. */
int mailbox_list_mkdir_missing_index_root(struct mailbox_list *list);
/* Like mailbox_list_mkdir_missing_index_root(), but for mailbox list
   index root. */
int mailbox_list_mkdir_missing_list_index_root(struct mailbox_list *list);

/* Returns TRUE if name is ok, FALSE if it can't be safely passed to
   mailbox_list_*() functions */
bool mailbox_list_is_valid_name(struct mailbox_list *list,
				const char *name, const char **error_r);

const char *mailbox_list_get_storage_name(struct mailbox_list *list,
					  const char *vname);
const char *mailbox_list_get_vname(struct mailbox_list *list, const char *name);

/* Get path to specified type of files in mailbox. Returns -1 if an error
   occurred (e.g. mailbox no longer exists), 0 if there are no files of this
   type (in-memory index, no alt dir, storage with no files), 1 if path was
   returned successfully. The path is set to NULL when returning -1/0. */
int mailbox_list_get_path(struct mailbox_list *list, const char *name,
			  enum mailbox_list_path_type type,
			  const char **path_r);
/* Get path to the root directory for files of specified type. Returns TRUE
   if path was returned, FALSE if there are no files of this type. */
bool mailbox_list_get_root_path(struct mailbox_list *list,
				enum mailbox_list_path_type type,
				const char **path_r);
/* Like mailbox_list_get_root_path(), but assume that the root directory
   exists (assert crash if not) */
const char *mailbox_list_get_root_forced(struct mailbox_list *list,
					 enum mailbox_list_path_type type);
/* Returns mailbox's change log, or NULL if it doesn't have one. */
struct mailbox_log *mailbox_list_get_changelog(struct mailbox_list *list);
/* Specify timestamp to use when writing mailbox changes to changelog.
   The same timestamp is used until stamp is set to (time_t)-1, after which
   current time is used */
void mailbox_list_set_changelog_timestamp(struct mailbox_list *list,
					  time_t stamp);

/* Returns a prefix that temporary files should use without conflicting
   with the namespace. */
const char *mailbox_list_get_temp_prefix(struct mailbox_list *list);
/* Returns prefix that's common to all get_temp_prefix() calls.
   Typically this returns either "temp." or ".temp.". */
const char *mailbox_list_get_global_temp_prefix(struct mailbox_list *list);

/* Subscribe/unsubscribe mailbox. There should be no error when
   subscribing to already subscribed mailbox. Subscribing to
   unexisting mailboxes is optional. */
int mailbox_list_set_subscribed(struct mailbox_list *list,
				const char *name, bool set);

/* Delete a non-selectable mailbox. Fail if the mailbox is selectable. */
int mailbox_list_delete_dir(struct mailbox_list *list, const char *name);
/* Delete a symlinked mailbox. Fail if the mailbox isn't a symlink. */
int mailbox_list_delete_symlink(struct mailbox_list *list, const char *name);

/* Returns the error message of last occurred error. */
const char * ATTR_NOWARN_UNUSED_RESULT
mailbox_list_get_last_error(struct mailbox_list *list,
			    enum mail_error *error_r);
/* Wrapper for mailbox_list_get_last_error() */
enum mail_error mailbox_list_get_last_mail_error(struct mailbox_list *list);

const char * ATTR_NOWARN_UNUSED_RESULT
mailbox_list_get_last_internal_error(struct mailbox_list *list,
				     enum mail_error *error_r);

/* Save the last error until it's popped. This is useful for cases where the
   list operation has already failed, but the cleanup code path changes the
   error to something else unwanted. */
void mailbox_list_last_error_push(struct mailbox_list *list);
void mailbox_list_last_error_pop(struct mailbox_list *list);

/* Create a fs based on the settings in the given mailbox_list. */
int mailbox_list_init_fs(struct mailbox_list *list, const char *driver,
			 const char *args, const char *root_dir,
			 struct fs **fs_r, const char **error_r);
/* Return mailbox_list that was used to create the fs via
   mailbox_list_init_fs(). */
struct mailbox_list *mailbox_list_fs_get_list(struct fs *fs);

#endif
