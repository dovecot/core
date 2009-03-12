#ifndef MAILBOX_LIST_H
#define MAILBOX_LIST_H

#include "mail-error.h"

struct mail_namespace;
struct mailbox_list;
struct mailbox_list_iterate_context;

enum mailbox_list_properties {
	/* maildir_name must always be empty */
	MAILBOX_LIST_PROP_NO_MAILDIR_NAME       = 0x01
};

enum mailbox_list_flags {
	/* Print debugging information while initializing the driver */
	MAILBOX_LIST_FLAG_DEBUG			= 0x01,
	/* Allow full filesystem access with absolute or relative paths. */
	MAILBOX_LIST_FLAG_FULL_FS_ACCESS	= 0x04,
	/* Rely on O_EXCL when creating dotlocks */
	MAILBOX_LIST_FLAG_DOTLOCK_USE_EXCL	= 0x08,
	/* Mailboxes are files, not directories. */
	MAILBOX_LIST_FLAG_MAILBOX_FILES		= 0x10,
	/* Flush NFS attribute cache when needed */
	MAILBOX_LIST_FLAG_NFS_FLUSH		= 0x20
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
	MAILBOX_MATCHED			= 0x40000000
};

enum mailbox_name_status {
	MAILBOX_NAME_EXISTS,
	MAILBOX_NAME_VALID,
	MAILBOX_NAME_INVALID,
	MAILBOX_NAME_NOINFERIORS
};

enum mailbox_list_iter_flags {
	/* Ignore index file and ACLs (used by ACL plugin internally) */
	MAILBOX_LIST_ITER_RAW_LIST		= 0x000001,
	/* Use virtual mailbox names (virtual separators and namespace
	   prefixes) for patterns and for returned mailbox names. */
	MAILBOX_LIST_ITER_VIRTUAL_NAMES		= 0x000002,

	/* List only subscribed mailboxes */
	MAILBOX_LIST_ITER_SELECT_SUBSCRIBED	= 0x000010,
	/* Return MAILBOX_CHILD_* if mailbox's children match selection
	   criteria, even if the mailbox itself wouldn't match. */
	MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH	= 0x000020,

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
	/* Return mailbox path (eg. ~/dbox/INBOX/dbox-Mails) */
	MAILBOX_LIST_PATH_TYPE_MAILBOX,
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
	const char *root_dir;
	const char *index_dir;
	const char *control_dir;

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

	/* If mailbox index is used, use these settings for it
	   (pointers, so they're set to NULL after init is finished): */
	const enum mail_storage_flags *mail_storage_flags;
	const enum file_lock_method *lock_method;
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

/* Returns 0 if ok, -1 if driver was unknown. */
int mailbox_list_alloc(const char *driver, struct mailbox_list **list_r,
		       const char **error_r);
void mailbox_list_init(struct mailbox_list *list, struct mail_namespace *ns,
		       const struct mailbox_list_settings *set,
		       enum mailbox_list_flags flags);
void mailbox_list_deinit(struct mailbox_list *list);

const char *
mailbox_list_get_driver_name(const struct mailbox_list *list) ATTR_PURE;
char mailbox_list_get_hierarchy_sep(const struct mailbox_list *list) ATTR_PURE;
enum mailbox_list_flags
mailbox_list_get_flags(const struct mailbox_list *list) ATTR_PURE;
struct mail_namespace *
mailbox_list_get_namespace(const struct mailbox_list *list) ATTR_PURE;

/* Returns the mode and GID that should be used when creating new global files
   to the mailbox list root directories. (gid_t)-1 is returned if it's not
   necessary to change the default */
void mailbox_list_get_permissions(struct mailbox_list *list,
				  mode_t *mode_r, gid_t *gid_r);
/* Like mailbox_list_get_permissions(), but add execute-bits for mode
   if either read or write bit is set (e.g. 0640 -> 0750). */
void mailbox_list_get_dir_permissions(struct mailbox_list *list,
				      mode_t *mode_r, gid_t *gid_r);

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
				  enum mailbox_list_iter_flags flags);
/* Get next mailbox. Returns the mailbox name */
const struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx);
/* Deinitialize mailbox list request. Returns -1 if some error
   occurred while listing. */
int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **ctx);

/* Subscribe/unsubscribe mailbox. There should be no error when
   subscribing to already subscribed mailbox. Subscribing to
   unexisting mailboxes is optional. */
int mailbox_list_set_subscribed(struct mailbox_list *list,
				const char *name, bool set);

/* Delete the given mailbox. If it has children, they aren't deleted. */
int mailbox_list_delete_mailbox(struct mailbox_list *list, const char *name);
/* If the name has inferior hierarchical names, then the inferior
   hierarchical names MUST also be renamed (ie. foo -> bar renames
   also foo/bar -> bar/bar). newname may contain multiple new
   hierarchies.

   If oldname is case-insensitively "INBOX", the mails are moved
   into new mailbox but the INBOX mailbox must not be deleted. */
int mailbox_list_rename_mailbox(struct mailbox_list *list,
				const char *oldname, const char *newname);

/* Returns the error message of last occurred error. */
const char *mailbox_list_get_last_error(struct mailbox_list *list,
					enum mail_error *error_r);

#endif
