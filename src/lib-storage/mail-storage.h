#ifndef __MAIL_STORAGE_H
#define __MAIL_STORAGE_H

struct message_size;

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

enum mailbox_sync_type {
	MAILBOX_SYNC_NONE,
	MAILBOX_SYNC_ALL,
	MAILBOX_SYNC_NO_EXPUNGES
};

enum modify_type {
	MODIFY_ADD,
	MODIFY_REMOVE,
	MODIFY_REPLACE
};

enum mail_sort_type {
/* Maximum size for sort program, 2x for reverse + END */
#define MAX_SORT_PROGRAM_SIZE (2*7 + 1)

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

enum mail_fetch_field {
	MAIL_FETCH_FLAGS		= 0x0001,
	MAIL_FETCH_MESSAGE_PARTS	= 0x0002,

	MAIL_FETCH_RECEIVED_DATE	= 0x0004,
	MAIL_FETCH_DATE			= 0x0008,
	MAIL_FETCH_SIZE			= 0x0010,

	MAIL_FETCH_STREAM_HEADER	= 0x0020,
	MAIL_FETCH_STREAM_BODY		= 0x0040,

	/* specials: */
	MAIL_FETCH_IMAP_BODY		= 0x1000,
	MAIL_FETCH_IMAP_BODYSTRUCTURE	= 0x2000,
	MAIL_FETCH_IMAP_ENVELOPE	= 0x4000
};

enum client_workarounds {
	WORKAROUND_OE6_FETCH_NO_NEWMAIL	= 0x01
};

struct mail_full_flags {
	enum mail_flags flags;

	const char **custom_flags;
	unsigned int custom_flags_count;
};

struct mail_storage;
struct mail_storage_callbacks;
struct mailbox_status;
struct mail_search_arg;
struct fetch_context;
struct search_context;

typedef void mailbox_list_callback_t(struct mail_storage *storage,
				     const char *name, enum mailbox_flags flags,
				     void *context);

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
			      mailbox_list_callback_t *callback, void *context);

	/* Subscribe/unsubscribe mailbox. There should be no error when
	   subscribing to already subscribed mailbox. Subscribing to
	   unexisting mailboxes is optional. */
	int (*set_subscribed)(struct mail_storage *storage,
			      const char *name, int set);

	/* Exactly like find_mailboxes(), but list only subscribed mailboxes. */
	int (*find_subscribed)(struct mail_storage *storage, const char *mask,
			       mailbox_list_callback_t *callback,
			       void *context);

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

	/* Synchronize mailbox in background. It's done until this function is
	   called with sync_type = MAILBOX_SYNC_NONE */
	void (*auto_sync)(struct mailbox *box, enum mailbox_sync_type sync_type,
			  unsigned int min_newmail_notify_interval);

	/* Expunge all mails with \Deleted flag. If notify is TRUE, call
	   expunge callbacks. Also always does full syncing. */
	int (*expunge)(struct mailbox *box, int notify);

	/* Update mail flags, calling update_flags callbacks. */
	int (*update_flags)(struct mailbox *box,
			    const char *messageset, int uidset,
			    const struct mail_full_flags *flags,
			    enum modify_type modify_type, int notify,
			    int *all_found);

	/* Copy mails to another mailbox. */
	int (*copy)(struct mailbox *box, struct mailbox *destbox,
		    const char *messageset, int uidset);

	/* Initialize new fetch request. wanted_fields isn't required, but it
	   can be used for optimizations. If *update_seen is TRUE, \Seen flag
	   is set for all fetched mails. *update_seen may be changed back to
	   FALSE if all mails are already seen, or if it's not possible to
	   change the flag (eg. read-only mailbox). */
	struct mail_fetch_context *
		(*fetch_init)(struct mailbox *box,
			      enum mail_fetch_field wanted_fields,
			      int *update_seen,
			      const char *messageset, int uidset);
	/* Deinitialize fetch request. all_found is set to TRUE if all of the
	   fetched messages were found (ie. not just deleted). */
	int (*fetch_deinit)(struct mail_fetch_context *ctx, int *all_found);
	/* Fetch the next message. Returned mail object can be used until
	   the next call to fetch_next() or fetch_deinit(). */
	struct mail *(*fetch_next)(struct mail_fetch_context *ctx);

	/* Simplified fetching for a single UID or sequence. Must be called
	   between fetch_init() .. fetch_deinit() or
	   search_init() .. search_deinit() */
	struct mail *(*fetch_uid)(struct mailbox *box, unsigned int uid,
				  enum mail_fetch_field wanted_fields);
	struct mail *(*fetch_seq)(struct mailbox *box, unsigned int seq,
				  enum mail_fetch_field wanted_fields);

	/* Modify sort_program to specify a sort program acceptable for
	   search_init(). If server supports no sorting, it's simply set to
	   {MAIL_SORT_END}. */
	int (*search_get_sorting)(struct mailbox *box,
				  enum mail_sort_type *sort_program);
	/* Initialize new search request. Search arguments are given so that
	   the storage can optimize the searching as it wants.

	   If sort_program is non-NULL, it requests that the returned messages
	   are sorted by the given criteria. sort_program must have gone
	   through search_get_sorting().

	   wanted_fields and wanted_headers aren't required, but they can be
	   used for optimizations. */
	struct mail_search_context *
		(*search_init)(struct mailbox *box, const char *charset,
			       struct mail_search_arg *args,
			       const enum mail_sort_type *sort_program,
			       enum mail_fetch_field wanted_fields,
			       const char *const wanted_headers[]);
	/* Deinitialize search request. */
	int (*search_deinit)(struct mail_search_context *ctx);
	/* Search the next message. Returned mail object can be used until
	   the next call to search_next() or search_deinit(). */
	struct mail *(*search_next)(struct mail_search_context *ctx);

	/* Initialize saving one or more mails. If transaction is TRUE, all
	   the saved mails are deleted if an error occurs or save_deinit()
	   is called with rollback TRUE. */
	struct mail_save_context *(*save_init)(struct mailbox *box,
					       int transaction);
	/* Deinitialize saving. rollback has effect only if save_init() was
	   called with transaction being TRUE. If rollback is FALSE but
	   committing the changes fails, all the commits are rollbacked if
	   possible. */
	int (*save_deinit)(struct mail_save_context *ctx, int rollback);
	/* Save a mail into mailbox. timezone_offset specifies the timezone in
	   minutes in which received_date was originally given with. */
	int (*save_next)(struct mail_save_context *ctx,
			 const struct mail_full_flags *flags,
			 time_t received_date, int timezone_offset,
			 struct istream *data);

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

struct mail {
	/* always set */
	unsigned int seq;
	unsigned int uid;

	unsigned int seen_updated:1; /* if update_seen was TRUE */

	const struct mail_full_flags *(*get_flags)(struct mail *mail);
	const struct message_part *(*get_parts)(struct mail *mail);

	/* Get the time message was received (IMAP INTERNALDATE).
	   Returns (time_t)-1 if error occured. */
	time_t (*get_received_date)(struct mail *mail);
	/* Get the Date-header in mail. Timezone is in minutes.
	   Returns (time_t)-1 if error occured, 0 if field wasn't found or
	   couldn't be parsed. */
	time_t (*get_date)(struct mail *mail, int *timezone);
	/* Get the full virtual size of mail (IMAP RFC822.SIZE).
	   Returns (uoff_t)-1 if error occured */
	uoff_t (*get_size)(struct mail *mail);

	/* Get value for single header field */
	const char *(*get_header)(struct mail *mail, const char *field);

	/* Returns the parsed address for given header field. */
	const struct message_address *(*get_address)(struct mail *mail,
						     const char *field);
	/* Returns the first mailbox (RFC2822 local-part) field for given
	   address header field. */
	const char *(*get_first_mailbox)(struct mail *mail, const char *field);

	/* Returns input stream pointing to beginning of message header.
	   hdr_size and body_size are updated unless they're NULL. */
	struct istream *(*get_stream)(struct mail *mail,
				      struct message_size *hdr_size,
				      struct message_size *body_size);

	/* Get the any of the "special" fields. */
	const char *(*get_special)(struct mail *mail,
				   enum mail_fetch_field field);
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

extern enum client_workarounds client_workarounds;
extern int full_filesystem_access;

/* Initialize mail storage. */
void mail_storage_init(void);

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
