#ifndef __MAIL_STORAGE_H
#define __MAIL_STORAGE_H

#include "imap-util.h"

enum mailbox_flags {
	MAILBOX_NOSELECT	= 0x01,
	MAILBOX_CHILDREN	= 0x02,
	MAILBOX_NOCHILDREN	= 0x04,
	MAILBOX_NOINFERIORS	= 0x08,
	MAILBOX_MARKED		= 0x10,
	MAILBOX_UNMARKED	= 0x20,

	MAILBOX_READONLY	= 0x40
};

enum mailbox_status_items {
	STATUS_MESSAGES		= 0x01,
	STATUS_RECENT		= 0x02,
	STATUS_UIDNEXT		= 0x04,
	STATUS_UIDVALIDITY	= 0x08,
	STATUS_UNSEEN		= 0x10,
	STATUS_FIRST_UNSEEN_SEQ	= 0x20,
	STATUS_CUSTOM_FLAGS	= 0x40
};

enum mailbox_name_status {
	MAILBOX_NAME_EXISTS,
	MAILBOX_NAME_VALID,
	MAILBOX_NAME_INVALID,
	MAILBOX_NAME_NOINFERIORS
};

enum modify_type {
	MODIFY_ADD,
	MODIFY_REMOVE,
	MODIFY_REPLACE
};

enum mail_sort_type {
	MAIL_SORT_ARRIVAL	= 0x0010,
	MAIL_SORT_CC		= 0x0020,
	MAIL_SORT_DATE		= 0x0040,
	MAIL_SORT_FROM		= 0x0080,
	MAIL_SORT_SIZE		= 0x0100,
	MAIL_SORT_SUBJECT	= 0x0200,
	MAIL_SORT_TO		= 0x0400,

	MAIL_SORT_REVERSE	= 0x0001, /* reverse the next type */

	MAIL_SORT_END		= 0x0000 /* ends sort program */
};

enum mail_thread_type {
	MAIL_THREAD_NONE,
	MAIL_THREAD_ORDEREDSUBJECT,
	MAIL_THREAD_REFERENCES
};

struct mail_storage;
struct mail_storage_callbacks;
struct mailbox_status;
struct mail_fetch_data;
struct mail_search_arg;

typedef void (*MailboxFunc)(struct mail_storage *storage, const char *name,
			    enum mailbox_flags flags, void *context);

/* All methods returning int return either TRUE or FALSE. */
struct mail_storage {
	char *name;

	char hierarchy_sep;

	/* Create new instance */
	struct mail_storage *(*create)(const char *data, const char *user);

	/* Free this instance */
	void (*free)(struct mail_storage *storage);

	/* Returns TRUE if this storage would accept the given data
	   as a valid parameter to create(). */
	int (*autodetect)(const char *data);

	/* Set storage callback functions to use. */
	void (*set_callbacks)(struct mail_storage *storage,
			      struct mail_storage_callbacks *callbacks,
			      void *context);

	/* Open a mailbox. If readonly is TRUE, mailbox must not be
	   modified in any way even when it's asked. If fast is TRUE,
	   any extra time consuming operations shouldn't be performed
	   (eg. when opening mailbox just for STATUS).

	   Note that append and copy may open the selected mailbox again
	   with possibly different readonly-state. */
	struct mailbox *(*open_mailbox)(struct mail_storage *storage,
					const char *name,
					int readonly, int fast);

	/* name is allowed to contain multiple new hierarchy levels. */
	int (*create_mailbox)(struct mail_storage *storage, const char *name);

	/* Only the specified mailbox is deleted, ie. folders under the
	   specified mailbox must not be deleted. */
	int (*delete_mailbox)(struct mail_storage *storage, const char *name);

	/* If the name has inferior hierarchical names, then the inferior
	   hierarchical names MUST also be renamed (ie. foo -> bar renames
	   also foo/bar -> bar/bar). newname may contain multiple new
	   hierarchies.

	   If oldname is case-insensitively "INBOX", the mails are moved
	   into new folder but the INBOX folder must not be deleted. */
	int (*rename_mailbox)(struct mail_storage *storage, const char *oldname,
			      const char *newname);

	/* Execute specified function for all mailboxes matching given
	   mask. The mask is in RFC2060 LIST format. */
	int (*find_mailboxes)(struct mail_storage *storage, const char *mask,
			      MailboxFunc func, void *context);

	/* Subscribe/unsubscribe mailbox. There should be no error when
	   subscribing to already subscribed mailbox. Subscribing to
	   unexisting mailboxes is optional. */
	int (*set_subscribed)(struct mail_storage *storage,
			      const char *name, int set);

	/* Exactly like find_mailboxes(), but list only subscribed mailboxes. */
	int (*find_subscribed)(struct mail_storage *storage, const char *mask,
			       MailboxFunc func, void *context);

	/* Returns mailbox name status */
	int (*get_mailbox_name_status)(struct mail_storage *storage,
				       const char *name,
				       enum mailbox_name_status *status);

	/* Returns the error message of last occured error. */
	const char *(*get_last_error)(struct mail_storage *storage,
				      int *syntax_error);

/* private: */
	char *dir; /* root directory */
	char *inbox_file; /* INBOX file for mbox */
	char *index_dir;

	char *user; /* name of user accessing the storage */
	char *error;

	struct mail_storage_callbacks *callbacks;
	void *callback_context;

	unsigned int syntax_error:1; /* Give a BAD reply instead of NO */
};

struct mailbox {
	char *name;

	struct mail_storage *storage;

	/* Close the box. Returns FALSE if some cleanup errors occured, but
	   the mailbox was closed anyway. */
	int (*close)(struct mailbox *box);

	/* Gets the mailbox status information. */
	int (*get_status)(struct mailbox *box, enum mailbox_status_items items,
			  struct mailbox_status *status);

	/* Synchronize the mailbox. If sync_expunges is FALSE, everything
	   but expunges are synced. */
	int (*sync)(struct mailbox *box, int sync_expunges);

	/* Expunge all mails with \Deleted flag. If notify is TRUE, call
	   expunge callbacks. Also always does full syncing. */
	int (*expunge)(struct mailbox *box, int notify);

	/* Update mail flags, calling update_flags callbacks. */
	int (*update_flags)(struct mailbox *box,
			    const char *messageset, int uidset,
			    enum mail_flags flags, const char *custom_flags[],
			    enum modify_type modify_type, int notify,
			    int *all_found);

	/* Copy mails to another mailbox. */
	int (*copy)(struct mailbox *box, struct mailbox *destbox,
		    const char *messageset, int uidset);

	/* Fetch wanted mail data. The results are written into output stream
	   in RFC2060 FETCH format. */
	int (*fetch)(struct mailbox *box, struct mail_fetch_data *fetch_data,
		     struct ostream *output, int *all_found);

	/* Search wanted mail data. args contains the search criteria.
	   Results are written into output stream in RFC2060 SEARCH format.
	   If charset is NULL, the given search strings are matched without
	   any conversion. */
	int (*search)(struct mailbox *box, const char *charset,
		      struct mail_search_arg *args,
		      enum mail_sort_type *sorting,
		      enum mail_thread_type threading,
		      struct ostream *output, int uid_result);

	/* Save a new mail into mailbox. timezone_offset specifies the
	   timezone in minutes which internal_date was originally given
	   with. */
	int (*save)(struct mailbox *box, enum mail_flags flags,
		    const char *custom_flags[],
		    time_t internal_date, int timezone_offset,
		    struct istream *data, uoff_t data_size);

	/* Returns TRUE if mailbox is now in inconsistent state, meaning that
	   the message IDs etc. may have changed - only way to recover this
	   would be to fully close the mailbox and reopen it. With IMAP
	   connection this would mean a forced disconnection since we can't
	   do forced CLOSE. */
	int (*is_inconsistency_error)(struct mailbox *box);

/* public: */
	unsigned int readonly:1;
	unsigned int allow_custom_flags:1;
/* private: */
	unsigned int inconsistent:1;
};

struct mailbox_status {
	unsigned int messages;
	unsigned int recent;
	unsigned int unseen;

	unsigned int uidvalidity;
	unsigned int uidnext;

	unsigned int first_unseen_seq;

	unsigned int diskspace_full:1;

	/* may be allocated from data stack */
	unsigned int custom_flags_count;
	const char **custom_flags;
};

struct mail_storage_callbacks {
	/* Alert: Not enough disk space */
	void (*alert_no_diskspace)(struct mailbox *mailbox, void *context);
	/* "* OK <text>" */
	void (*notify_ok)(struct mailbox *mailbox, const char *text,
			  void *context);
	/* "* NO <text>" */
	void (*notify_no)(struct mailbox *mailbox, const char *text,
			  void *context);

	/* EXPUNGE */
	void (*expunge)(struct mailbox *mailbox, unsigned int seq,
			void *context);
	/* FETCH FLAGS */
	void (*update_flags)(struct mailbox *mailbox, unsigned int seq,
			     unsigned int uid, enum mail_flags flags,
			     const char *custom_flags[],
			     unsigned int custom_flags_count, void *context);

	/* EXISTS, RECENT */
	void (*new_messages)(struct mailbox *mailbox,
			     unsigned int messages_count,
			     unsigned int recent_count, void *context);
	/* FLAGS, PERMANENTFLAGS */
	void (*new_custom_flags)(struct mailbox *mailbox,
				 const char *custom_flags[],
				 unsigned int custom_flags_count,
				 void *context);

};

struct mail_fetch_data {
	const char *messageset;
	unsigned int uidset:1;

	unsigned int body:1;
	unsigned int bodystructure:1;
	unsigned int envelope:1;
	unsigned int flags:1;
	unsigned int internaldate:1;
	unsigned int rfc822:1;
	unsigned int rfc822_header:1;
	unsigned int rfc822_size:1;
	unsigned int rfc822_text:1;
	unsigned int uid:1;

	struct mail_fetch_body_data *body_sections;
};

struct mail_fetch_body_data {
	struct mail_fetch_body_data *next;

	const char *section; /* NOTE: always uppercased */
	uoff_t skip, max_size; /* if you don't want max_size,
	                          set it to (uoff_t)-1 */
	unsigned int skip_set:1;
	unsigned int peek:1;
};

/* register all mail storages */
void mail_storage_register_all(void);

/* Register mail storage class with given name - all methods that are NULL
   are set to default methods */
void mail_storage_class_register(struct mail_storage *storage_class);
void mail_storage_class_unregister(struct mail_storage *storage_class);

/* Create a new instance of registered mail storage class with given
   storage-specific data. If data is NULL, it tries to use defaults.
   May return NULL if anything fails. */
struct mail_storage *mail_storage_create(const char *name, const char *data,
					 const char *user);
void mail_storage_destroy(struct mail_storage *storage);

struct mail_storage *mail_storage_create_default(const char *user);
struct mail_storage *mail_storage_create_with_data(const char *data,
						   const char *user);

/* Set error message in storage. Critical errors are logged with i_error(),
   but user sees only "internal error" message. */
void mail_storage_clear_error(struct mail_storage *storage);
void mail_storage_set_error(struct mail_storage *storage,
			    const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_syntax_error(struct mail_storage *storage,
				   const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_critical(struct mail_storage *storage,
			       const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_internal_error(struct mail_storage *storage);

const char *mail_storage_get_last_error(struct mail_storage *storage,
					int *syntax);
int mail_storage_is_inconsistency_error(struct mailbox *box);

#endif
