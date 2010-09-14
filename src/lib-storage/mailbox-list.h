#ifndef MAILBOX_LIST_H
#define MAILBOX_LIST_H

#include "mail-types.h"
#include "mail-error.h"

#ifdef PATH_MAX
#  define MAILBOX_LIST_NAME_MAX_LENGTH PATH_MAX
#else
#  define MAILBOX_LIST_NAME_MAX_LENGTH 4096
#endif

enum namespace_type;
struct mail_namespace;
struct mail_storage;
struct mailbox_list;
struct mailbox_list_iterate_context;

enum mailbox_list_properties {
	/* maildir_name must always be empty */
	MAILBOX_LIST_PROP_NO_MAILDIR_NAME	= 0x01,
	/* alt directories not supported */
	MAILBOX_LIST_PROP_NO_ALT_DIR		= 0x02,
	/* no support for \noselect directories, only mailboxes */
	MAILBOX_LIST_PROP_NO_NOSELECT		= 0x04,
	/* mail root directory isn't required */
	MAILBOX_LIST_PROP_NO_ROOT		= 0x08
};

enum mailbox_list_flags {
	/* Mailboxes are files, not directories. */
	MAILBOX_LIST_FLAG_MAILBOX_FILES		= 0x01
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

	/* Internally used by lib-storage */
	MAILBOX_SELECT			= 0x20000000,
	MAILBOX_MATCHED			= 0x40000000
};

enum mailbox_name_status {
	/* name points to a selectable mailbox */
	MAILBOX_NAME_EXISTS_MAILBOX,
	/* name points to non-selectable mailbox */
	MAILBOX_NAME_EXISTS_DIR,
	MAILBOX_NAME_VALID,
	MAILBOX_NAME_INVALID,
	MAILBOX_NAME_NOINFERIORS
};

enum mailbox_list_iter_flags {
	/* Ignore index file and ACLs (used by ACL plugin internally) */
	MAILBOX_LIST_ITER_RAW_LIST		= 0x000001,
	/* When listing "foo/%" and "foo" is an existing mailbox
	   (maybe \noselect), have LIST also return "foo/" in the replies.
	   This is needed by IMAP, but messes up internal code. */
	MAILBOX_LIST_ITER_SHOW_EXISTING_PARENT	= 0x000002,
	/* Don't list INBOX unless it actually exists */
	MAILBOX_LIST_ITER_NO_AUTO_INBOX		= 0x000004,

	/* For mailbox_list_iter_init_namespaces(): Skip namespaces that
	   have alias_for set. */
	MAILBOX_LIST_ITER_SKIP_ALIASES		= 0x000008,
	/* For mailbox_list_iter_init_namespaces(): '*' in a pattern doesn't
	   match beyond namespace boundary (e.g. "foo*" or "*o" doesn't match
	   "foo." namespace's mailboxes, but "*.*" does). also '%' can't match
	   namespace prefixes, if there exists a parent namespace whose children
	   it matches. */
	MAILBOX_LIST_ITER_STAR_WITHIN_NS	= 0x000010,

	/* List only subscribed mailboxes */
	MAILBOX_LIST_ITER_SELECT_SUBSCRIBED	= 0x000100,
	/* Return MAILBOX_CHILD_* if mailbox's children match selection
	   criteria, even if the mailbox itself wouldn't match. */
	MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH	= 0x000200,

	/* Don't return any flags unless it can be done without cost */
	MAILBOX_LIST_ITER_RETURN_NO_FLAGS	= 0x001000,
	/* Return MAILBOX_SUBSCRIBED flag */
	MAILBOX_LIST_ITER_RETURN_SUBSCRIBED	= 0x002000,
	/* Return children flags */
	MAILBOX_LIST_ITER_RETURN_CHILDREN	= 0x004000
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
	/* Return index file directory */
	MAILBOX_LIST_PATH_TYPE_INDEX
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
	const char *control_dir;
	const char *alt_dir; /* FIXME: dbox-specific.. */

	const char *inbox_path;
	const char *subscription_fname;
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
};

struct mailbox_info {
	const char *name;
	enum mailbox_info_flags flags;
	struct mail_namespace *ns;
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
			enum mailbox_list_flags flags, const char **error_r);
void mailbox_list_destroy(struct mailbox_list **list);

const char *
mailbox_list_get_driver_name(const struct mailbox_list *list) ATTR_PURE;
enum mailbox_list_flags
mailbox_list_get_flags(const struct mailbox_list *list) ATTR_PURE;
struct mail_namespace *
mailbox_list_get_namespace(const struct mailbox_list *list) ATTR_PURE;
struct mail_user *
mailbox_list_get_user(const struct mailbox_list *list) ATTR_PURE;
int mailbox_list_get_storage(struct mailbox_list **list, const char **name,
			     struct mail_storage **storage_r);
void mailbox_list_get_closest_storage(struct mailbox_list *list,
				      struct mail_storage **storage);

/* Returns the mode and GID that should be used when creating new files to
   the specified mailbox, or to mailbox list root if name is NULL. (gid_t)-1 is
   returned if it's not necessary to change the default gid. */
void mailbox_list_get_permissions(struct mailbox_list *list,
				  const char *name,
				  mode_t *mode_r, gid_t *gid_r,
				  const char **gid_origin_r);
/* Like mailbox_list_get_permissions(), but add execute-bits for mode
   if either read or write bit is set (e.g. 0640 -> 0750). */
void mailbox_list_get_dir_permissions(struct mailbox_list *list,
				      const char *name,
				      mode_t *mode_r, gid_t *gid_r,
				      const char **gid_origin_r);
/* Create path's parent directory with proper permissions. Since most
   directories are created lazily, this function can be used to easily create
   them whenever file creation fails with ENOENT. */
int mailbox_list_create_parent_dir(struct mailbox_list *list,
				   const char *mailbox, const char *path);

/* Returns TRUE if the name doesn't contain any invalid characters.
   The create name check can be more strict. */
bool mailbox_list_is_valid_pattern(struct mailbox_list *list,
				   const char *pattern);
bool mailbox_list_is_valid_existing_name(struct mailbox_list *list,
					 const char *name);
bool mailbox_list_is_valid_create_name(struct mailbox_list *list,
				       const char *name);

/* Return full path for the given mailbox name. The name must be a valid
   existing mailbox name, or NULL to get the root directory.
   For INDEX=MEMORY it returns "" as the path. */
const char *mailbox_list_get_path(struct mailbox_list *list, const char *name,
				  enum mailbox_list_path_type type);
/* Returns mailbox name status */
int mailbox_list_get_mailbox_name_status(struct mailbox_list *list,
					 const char *name,
					 enum mailbox_name_status *status);
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

/* Returns a single pattern from given reference and pattern. */
const char *mailbox_list_join_refpattern(struct mailbox_list *list,
					 const char *ref, const char *pattern);

/* Initialize new mailbox list request. Pattern may contain '%' and '*'
   wildcards as defined by RFC-3501. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *pattern,
		       enum mailbox_list_iter_flags flags);
/* Like mailbox_list_iter_init(), but support multiple patterns. Patterns is
   a NULL-terminated list of strings. It must contain at least one pattern. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init_multiple(struct mailbox_list *list,
				const char *const *patterns,
				enum mailbox_list_iter_flags flags);
/* List mailbox_list_iter_init_multiple(), but list mailboxes from all the
   specified namespaces. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init_namespaces(struct mail_namespace *namespaces,
				  const char *const *patterns,
				  enum namespace_type type_mask,
				  enum mailbox_list_iter_flags flags);
/* Get next mailbox. Returns the mailbox name */
const struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx);
/* Deinitialize mailbox list request. Returns -1 if some error
   occurred while listing. */
int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **ctx);
/* List one mailbox. Returns 1 if info returned, 0 if mailbox doesn't exist,
   -1 if error. */
int mailbox_list_mailbox(struct mailbox_list *list, const char *name,
			 enum mailbox_info_flags *flags_r);

/* Subscribe/unsubscribe mailbox. There should be no error when
   subscribing to already subscribed mailbox. Subscribing to
   unexisting mailboxes is optional. */
int mailbox_list_set_subscribed(struct mailbox_list *list,
				const char *name, bool set);

/* Create a non-selectable mailbox. Fail with MAIL_ERROR_NOTPOSSIBLE if only
   a selectable mailbox can be created. */
int mailbox_list_create_dir(struct mailbox_list *list, const char *name);
/* Delete a non-selectable mailbox. Fail if the mailbox is selectable. */
int mailbox_list_delete_dir(struct mailbox_list *list, const char *name);

/* Returns the error message of last occurred error. */
const char *mailbox_list_get_last_error(struct mailbox_list *list,
					enum mail_error *error_r);

#endif
