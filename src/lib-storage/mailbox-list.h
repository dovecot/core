#ifndef __MAILBOX_LIST_H
#define __MAILBOX_LIST_H

struct mailbox_list;
struct mailbox_list_iterate_context;

enum mailbox_list_flags {
	/* Print debugging information while initializing the driver */
	MAILBOX_LIST_FLAG_DEBUG			= 0x01,
	/* This mailbox list contains INBOX. Match case-insensitively for it. */
	MAILBOX_LIST_FLAG_INBOX			= 0x02,
	/* Allow full filesystem access with absolute or relative paths. */
	MAILBOX_LIST_FLAG_FULL_FS_ACCESS	= 0x04,
	/* Rely on O_EXCL when creating dotlocks */
	MAILBOX_LIST_FLAG_DOTLOCK_USE_EXCL	= 0x08
};

enum mailbox_info_flags {
	MAILBOX_NOSELECT	= 0x001,
	MAILBOX_NONEXISTENT	= 0x002,
	MAILBOX_CHILDREN	= 0x004,
	MAILBOX_NOCHILDREN	= 0x008,
	MAILBOX_NOINFERIORS	= 0x010,
	MAILBOX_MARKED		= 0x020,
	MAILBOX_UNMARKED	= 0x040
};

enum mailbox_name_status {
	MAILBOX_NAME_EXISTS,
	MAILBOX_NAME_VALID,
	MAILBOX_NAME_INVALID,
	MAILBOX_NAME_NOINFERIORS
};

enum mailbox_list_iter_flags {
	/* List only subscribed mailboxes */
	MAILBOX_LIST_ITER_SUBSCRIBED	= 0x01,
	/* Don't return any flags unless it can be done without cost */
	MAILBOX_LIST_ITER_FAST_FLAGS	= 0x02,
	/* Return children flags */
	MAILBOX_LIST_ITER_CHILDREN	= 0x04
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

	/* If mailbox index is used, use these settings for it
	   (pointers, so they're set to NULL after init is finished): */
	const enum mail_storage_flags *mail_storage_flags;
	const enum file_lock_method *lock_method;
};

struct mailbox_info {
	const char *name;
        enum mailbox_info_flags flags;
};

/* register all drivers */
void mailbox_list_register_all(void);

void mailbox_list_register(const struct mailbox_list *list);
void mailbox_list_unregister(const struct mailbox_list *list);

/* Returns 0 if ok, -1 if initialization failed. */
int mailbox_list_init(const char *driver,
		      const struct mailbox_list_settings *set,
		      enum mailbox_list_flags flags,
		      struct mailbox_list **list_r, const char **error_r);
void mailbox_list_deinit(struct mailbox_list *list);

const char *mailbox_list_get_driver_name(struct mailbox_list *list);
char mailbox_list_get_hierarchy_sep(struct mailbox_list *list);

/* Returns TRUE if the name doesn't contain any invalid characters.
   The create name check can be more strict. */
bool mailbox_list_is_valid_mask(struct mailbox_list *list, const char *mask);
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

/* Returns a single mask from given reference and mask. */
const char *mailbox_list_join_refmask(struct mailbox_list *list,
				      const char *ref, const char *mask);

/* Initialize new mailbox list request. mask may contain '%' and '*'
   wildcards as defined by RFC-3501. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *mask,
		       enum mailbox_list_iter_flags flags);
/* Get next mailbox. Returns the mailbox name */
struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx);
/* Deinitialize mailbox list request. Returns FALSE if some error
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
					bool *temporary_error_r);

#endif
