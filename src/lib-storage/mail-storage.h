#ifndef __MAIL_STORAGE_H
#define __MAIL_STORAGE_H

struct message_size;

#include "mail-types.h"

enum mailbox_open_flags {
	MAILBOX_OPEN_READONLY		= 0x01,
	MAILBOX_OPEN_FAST		= 0x02,
	MAILBOX_OPEN_KEEP_RECENT	= 0x04
};

enum mailbox_list_flags {
	MAILBOX_LIST_SUBSCRIBED	= 0x01,
	MAILBOX_LIST_FAST_FLAGS	= 0x02,
	MAILBOX_LIST_CHILDREN	= 0x04
};

enum mailbox_flags {
	MAILBOX_NOSELECT	= 0x001,
	MAILBOX_NONEXISTENT	= 0x002,
	MAILBOX_PLACEHOLDER	= 0x004,
	MAILBOX_CHILDREN	= 0x008,
	MAILBOX_NOCHILDREN	= 0x010,
	MAILBOX_NOINFERIORS	= 0x020,
	MAILBOX_MARKED		= 0x040,
	MAILBOX_UNMARKED	= 0x080,

	MAILBOX_READONLY	= 0x100
};

enum mailbox_status_items {
	STATUS_MESSAGES		= 0x01,
	STATUS_RECENT		= 0x02,
	STATUS_UIDNEXT		= 0x04,
	STATUS_UIDVALIDITY	= 0x08,
	STATUS_UNSEEN		= 0x10,
	STATUS_FIRST_UNSEEN_SEQ	= 0x20,
	STATUS_KEYWORDS		= 0x40
};

enum mailbox_name_status {
	MAILBOX_NAME_EXISTS,
	MAILBOX_NAME_VALID,
	MAILBOX_NAME_INVALID,
	MAILBOX_NAME_NOINFERIORS
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
	MAIL_FETCH_IMAP_ENVELOPE	= 0x4000,
	MAIL_FETCH_FROM_ENVELOPE	= 0x8000
};

enum mailbox_sync_flags {
	MAILBOX_SYNC_FLAG_FAST		= 0x01,
	MAILBOX_SYNC_FLAG_NO_EXPUNGES	= 0x02,
	MAILBOX_SYNC_AUTO_STOP		= 0x04
};

enum client_workarounds {
	WORKAROUND_OE6_FETCH_NO_NEWMAIL		= 0x01,
	WORKAROUND_OUTLOOK_IDLE			= 0x02
};

struct mail_storage;
struct mail_storage_callbacks;
struct mailbox_list;
struct mailbox_status;
struct mail_search_arg;
struct fetch_context;
struct search_context;
struct mail;
struct mailbox;
struct mailbox_list_context;
struct mailbox_transaction_context;

struct mailbox_list {
	const char *name;
        enum mailbox_flags flags;
};

struct mailbox_status {
	uint32_t messages;
	uint32_t recent;
	uint32_t unseen;

	uint32_t uidvalidity;
	uint32_t uidnext;

	uint32_t first_unseen_seq;

	unsigned int diskspace_full:1;

	/* may be allocated from data stack */
	unsigned int keywords_count;
	const char **keywords;
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
			     const struct mail_full_flags *flags,
			     void *context);

	/* EXISTS */
	void (*message_count_changed)(struct mailbox *mailbox,
				      unsigned int count, void *context);
	/* RECENT */
	void (*recent_count_changed)(struct mailbox *mailbox,
				     unsigned int count, void *context);
	/* FLAGS, PERMANENTFLAGS */
	void (*new_keywords)(struct mailbox *mailbox,
			     const char *keywords[],
			     unsigned int keywords_count, void *context);

};

extern enum client_workarounds client_workarounds;
extern int full_filesystem_access;

void mail_storage_init(void);
void mail_storage_deinit(void);

/* register all mail storages */
void mail_storage_register_all(void);

/* Register mail storage class with given name - all methods that are NULL
   are set to default methods */
void mail_storage_class_register(struct mail_storage *storage_class);
void mail_storage_class_unregister(struct mail_storage *storage_class);

/* Create a new instance of registered mail storage class with given
   storage-specific data. If data is NULL, it tries to use defaults.
   May return NULL if anything fails.

   If namespace is non-NULL, all mailbox names are expected to begin with it.
   hierarchy_sep overrides the default separator if it's not '\0'. */
struct mail_storage *
mail_storage_create(const char *name, const char *data, const char *user,
		    const char *namespace, char hierarchy_sep);
void mail_storage_destroy(struct mail_storage *storage);

struct mail_storage *
mail_storage_create_default(const char *user,
			    const char *namespace, char hierarchy_sep);
struct mail_storage *
mail_storage_create_with_data(const char *data, const char *user,
			      const char *namespace, char hierarchy_sep);

char mail_storage_get_hierarchy_sep(struct mail_storage *storage);

/* Set storage callback functions to use. */
void mail_storage_set_callbacks(struct mail_storage *storage,
				struct mail_storage_callbacks *callbacks,
				void *context);

/* name is allowed to contain multiple new hierarchy levels.
   If directory is TRUE, the mailbox should be created so that it
   can contain children. The mailbox itself doesn't have to be
   created as long as it shows in LIST. */
int mail_storage_mailbox_create(struct mail_storage *storage, const char *name,
				int directory);
/* Only the specified mailbox is deleted, ie. folders under the
   specified mailbox must not be deleted. */
int mail_storage_mailbox_delete(struct mail_storage *storage, const char *name);
/* If the name has inferior hierarchical names, then the inferior
   hierarchical names MUST also be renamed (ie. foo -> bar renames
   also foo/bar -> bar/bar). newname may contain multiple new
   hierarchies.

   If oldname is case-insensitively "INBOX", the mails are moved
   into new folder but the INBOX folder must not be deleted. */
int mail_storage_mailbox_rename(struct mail_storage *storage,
				const char *oldname, const char *newname);

/* Initialize new mailbox list request. mask may contain '%' and '*'
   wildcards as defined in RFC2060. Matching against "INBOX" is
   case-insensitive, but anything else is not. */
struct mailbox_list_context *
mail_storage_mailbox_list_init(struct mail_storage *storage,
			       const char *mask,
			       enum mailbox_list_flags flags);
/* Get next mailbox. Returns the mailbox name */
struct mailbox_list *
mail_storage_mailbox_list_next(struct mailbox_list_context *ctx);
/* Deinitialize mailbox list request. Returns FALSE if some error
   occured while listing. */
int mail_storage_mailbox_list_deinit(struct mailbox_list_context *ctx);

/* Subscribe/unsubscribe mailbox. There should be no error when
   subscribing to already subscribed mailbox. Subscribing to
   unexisting mailboxes is optional. */
int mail_storage_set_subscribed(struct mail_storage *storage,
				const char *name, int set);

/* Returns mailbox name status */
int mail_storage_get_mailbox_name_status(struct mail_storage *storage,
					 const char *name,
					 enum mailbox_name_status *status);

/* Returns the error message of last occured error. */
const char *mail_storage_get_last_error(struct mail_storage *storage,
					int *syntax_error_r);

/* Open a mailbox. If readonly is TRUE, mailbox must not be
   modified in any way even when it's asked. If fast is TRUE,
   any extra time consuming operations shouldn't be performed
   (eg. when opening mailbox just for STATUS).

   Note that append and copy may open the selected mailbox again
   with possibly different readonly-state. */
struct mailbox *mailbox_open(struct mail_storage *storage,
			     const char *name, enum mailbox_open_flags flags);
/* Close the box. Returns FALSE if some cleanup errors occured, but
   the mailbox was closed anyway. */
int mailbox_close(struct mailbox *box);

/* Returns storage of given mailbox */
struct mail_storage *mailbox_get_storage(struct mailbox *box);

/* Returns name of given mailbox */
const char *mailbox_get_name(struct mailbox *box);

/* Returns TRUE if mailbox is read-only. */
int mailbox_is_readonly(struct mailbox *box);

/* Returns TRUE if mailbox currently supports adding keywords. */
int mailbox_allow_new_keywords(struct mailbox *box);

/* Gets the mailbox status information. */
int mailbox_get_status(struct mailbox *box,
		       enum mailbox_status_items items,
		       struct mailbox_status *status);

/* Synchronize the mailbox. */
int mailbox_sync(struct mailbox *box, enum mailbox_sync_flags flags);

/* Synchronize mailbox in background. It's done until this function is
   called with flags = MAILBOX_SYNC_AUTO_STOP. */
void mailbox_auto_sync(struct mailbox *box, enum mailbox_sync_flags flags,
		       unsigned int min_newmail_notify_interval);

struct mailbox_transaction_context *
mailbox_transaction_begin(struct mailbox *box, int hide);
int mailbox_transaction_commit(struct mailbox_transaction_context *t);
void mailbox_transaction_rollback(struct mailbox_transaction_context *t);

/* Simplified fetching for a single sequence. */
struct mail *mailbox_fetch(struct mailbox_transaction_context *t, uint32_t seq,
			   enum mail_fetch_field wanted_fields);

/* Convert uid range to sequence range. */
int mailbox_get_uids(struct mailbox *box, uint32_t uid1, uint32_t uid2,
		     uint32_t *seq1_r, uint32_t *seq2_r);

/* Modify sort_program to specify a sort program acceptable for
   search_init(). If mailbox supports no sorting, it's simply set to
   {MAIL_SORT_END}. */
int mailbox_search_get_sorting(struct mailbox *box,
			       enum mail_sort_type *sort_program);
/* Initialize new search request. Search arguments are given so that
   the storage can optimize the searching as it wants.

   If sort_program is non-NULL, it requests that the returned messages
   are sorted by the given criteria. sort_program must have gone
   through search_get_sorting().

   wanted_fields and wanted_headers aren't required, but they can be
   used for optimizations. */
struct mail_search_context *
mailbox_search_init(struct mailbox_transaction_context *t,
		    const char *charset, struct mail_search_arg *args,
		    const enum mail_sort_type *sort_program,
		    enum mail_fetch_field wanted_fields,
		    const char *const wanted_headers[]);
/* Deinitialize search request. */
int mailbox_search_deinit(struct mail_search_context *ctx);
/* Search the next message. Returned mail object can be used until
   the next call to search_next() or search_deinit(). */
struct mail *mailbox_search_next(struct mail_search_context *ctx);

/* Save a mail into mailbox. timezone_offset specifies the timezone in
   minutes in which received_date was originally given with. To use
   current time, set received_date to (time_t)-1. */
int mailbox_save(struct mailbox_transaction_context *t,
		 const struct mail_full_flags *flags,
		 time_t received_date, int timezone_offset,
		 const char *from_envelope, struct istream *data);
/* Copy given message. */
int mailbox_copy(struct mailbox_transaction_context *t, struct mail *mail);

/* Returns TRUE if mailbox is now in inconsistent state, meaning that
   the message IDs etc. may have changed - only way to recover this
   would be to fully close the mailbox and reopen it. With IMAP
   connection this would mean a forced disconnection since we can't
   do forced CLOSE. */
int mailbox_is_inconsistent(struct mailbox *box);

struct mail {
	/* always set */
	struct mailbox *box;
	uint32_t seq, uid;

	unsigned int expunged:1;
	unsigned int has_nuls:1; /* message data is known to contain NULs */
	unsigned int has_no_nuls:1; /* -''- known to not contain NULs */

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
	/* Returns partial headers which contain _at least_ the given fields,
	   but it may contain others as well. */
	struct istream *(*get_headers)(struct mail *mail,
				       const char *const minimum_fields[]);

	/* Returns input stream pointing to beginning of message header.
	   hdr_size and body_size are updated unless they're NULL. */
	struct istream *(*get_stream)(struct mail *mail,
				      struct message_size *hdr_size,
				      struct message_size *body_size);

	/* Get the any of the "special" fields. */
	const char *(*get_special)(struct mail *mail,
				   enum mail_fetch_field field);

	/* Update message flags. */
	int (*update_flags)(struct mail *mail,
			    const struct mail_full_flags *flags,
			    enum modify_type modify_type);

	/* Expunge this message. Sequence numbers don't change until commit. */
	int (*expunge)(struct mail *mail);
};

#endif
