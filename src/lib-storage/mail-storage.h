#ifndef __MAIL_STORAGE_H
#define __MAIL_STORAGE_H

#include "imap-util.h"
#include "imap-parser.h"

typedef enum {
	MAILBOX_NOSELECT	= 0x01,
	MAILBOX_CHILDREN	= 0x02,
	MAILBOX_NOCHILDREN	= 0x04,
	MAILBOX_NOINFERIORS	= 0x08,
	MAILBOX_MARKED		= 0x10,
	MAILBOX_UNMARKED	= 0x20,

	MAILBOX_READONLY	= 0x40
} MailboxFlags;

typedef enum {
	STATUS_MESSAGES		= 0x01,
	STATUS_RECENT		= 0x02,
	STATUS_UIDNEXT		= 0x04,
	STATUS_UIDVALIDITY	= 0x08,
	STATUS_UNSEEN		= 0x10,
	STATUS_FIRST_UNSEEN_SEQ	= 0x20,
	STATUS_CUSTOM_FLAGS	= 0x40
} MailboxStatusItems;

typedef enum {
	MAILBOX_NAME_EXISTS,
	MAILBOX_NAME_VALID,
	MAILBOX_NAME_INVALID
} MailboxNameStatus;

typedef enum {
	MODIFY_ADD,
	MODIFY_REMOVE,
	MODIFY_REPLACE
} ModifyType;

typedef struct _MailStorage MailStorage;
typedef struct _Mailbox Mailbox;
typedef struct _MailboxStatus MailboxStatus;
typedef struct _MailboxSyncCallbacks MailboxSyncCallbacks;
typedef struct _MailFetchData MailFetchData;
typedef struct _MailFetchBodyData MailFetchBodyData;
typedef struct _MailSearchArg MailSearchArg;

typedef void (*MailboxFunc)(MailStorage *storage, const char *name,
			    MailboxFlags flags, void *context);

/* All methods returning int return either TRUE or FALSE. */
struct _MailStorage {
	char *name;

	char hierarchy_sep;

	/* Create new instance */
	MailStorage *(*create)(const char *data, const char *user);

	/* Free this instance */
	void (*free)(MailStorage *storage);

	/* Returns TRUE if this storage would accept the given data
	   as a valid parameter to create(). */
	int (*autodetect)(const char *data);

	/* Open a mailbox. If readonly is TRUE, mailbox must not be
	   modified in any way even when it's asked. If fast is TRUE,
	   any extra time consuming operations shouldn't be performed
	   (eg. when opening mailbox just for STATUS).

	   Note that append and copy may open the selected mailbox again
	   with possibly different readonly-state. */
	Mailbox *(*open_mailbox)(MailStorage *storage, const char *name,
				 int readonly, int fast);

	/* name is allowed to contain multiple new hierarchy levels */
	int (*create_mailbox)(MailStorage *storage, const char *name);
	int (*delete_mailbox)(MailStorage *storage, const char *name);

	/* If the name has inferior hierarchical names, then the inferior
	   hierarchical names MUST also be renamed (ie. foo -> bar renames
	   also foo/bar -> bar/bar).

	   If oldname is case-insensitively "INBOX", the mails are moved
	   into new folder but the INBOX folder must not be deleted. */
	int (*rename_mailbox)(MailStorage *storage, const char *oldname,
			      const char *newname);

	/* Execute specified function for all mailboxes matching given
	   mask. The mask is in RFC2060 LIST format. */
	int (*find_mailboxes)(MailStorage *storage, const char *mask,
			      MailboxFunc func, void *context);

	/* Subscribe/unsubscribe mailbox. There should be no error when
	   subscribing to already subscribed mailbox. Subscribing to
	   unexisting mailboxes is optional. */
	int (*set_subscribed)(MailStorage *storage, const char *name, int set);

	/* Exactly like find_mailboxes(), but list only subscribed mailboxes. */
	int (*find_subscribed)(MailStorage *storage, const char *mask,
			       MailboxFunc func, void *context);

	/* Returns mailbox name status */
	int (*get_mailbox_name_status)(MailStorage *storage, const char *name,
				       MailboxNameStatus *status);

	/* Returns the error message of last occured error. */
	const char *(*get_last_error)(MailStorage *storage);

/* private: */
	char *dir; /* root directory */
	char *user; /* name of user accessing the storage */
	char *error;
};

struct _Mailbox {
	char *name;

	MailStorage *storage;

	/* Close the box. Returns FALSE if some cleanup errors occured, but
	   the mailbox was closed anyway. */
	int (*close)(Mailbox *box);

	/* Set synchronization callback functions to use. */
	void (*set_sync_callbacks)(Mailbox *box,
				   MailboxSyncCallbacks *callbacks,
				   void *context);

	/* Gets the mailbox status information. */
	int (*get_status)(Mailbox *box, MailboxStatusItems items,
			  MailboxStatus *status);

	/* Synchronize the mailbox. If sync_expunges is FALSE, everything
	   but expunges are synced. */
	int (*sync)(Mailbox *box, int sync_expunges);

	/* Expunge all mails with \Deleted flag. If notify is TRUE, call
	   expunge callbacks. Also always does full syncing. */
	int (*expunge)(Mailbox *box, int notify);

	/* Update mail flags, calling update_flags callbacks. */
	int (*update_flags)(Mailbox *box, const char *messageset, int uidset,
			    MailFlags flags, const char *custom_flags[],
			    ModifyType modify_type, int notify, int *all_found);

	/* Copy mails to another mailbox. */
	int (*copy)(Mailbox *box, Mailbox *destbox,
		    const char *messageset, int uidset);

	/* Fetch wanted mail data. The results are written into outbuf
	   in RFC2060 FETCH format. */
	int (*fetch)(Mailbox *box, MailFetchData *fetch_data,
		     OBuffer *outbuf, int *all_found);

	/* Search wanted mail data. args contains the search criteria.
	   results are written into outbuf in RFC2060 SEARCH format. */
	int (*search)(Mailbox *box, MailSearchArg *args,
		      OBuffer *outbuf, int uid_result);

	/* Save a new mail into mailbox. timezone_offset specifies the
	   timezone in minutes which internal_date was originally given
	   with. */
	int (*save)(Mailbox *box, MailFlags flags, const char *custom_flags[],
		    time_t internal_date, int timezone_offset,
		    IBuffer *data, uoff_t data_size);

	/* Returns TRUE if mailbox is now in inconsistent state, meaning that
	   the message IDs etc. may have changed - only way to recover this
	   would be to fully close the mailbox and reopen it. With IMAP
	   connection this would mean a forced disconnection since we can't
	   do forced CLOSE. */
	int (*is_inconsistency_error)(Mailbox *box);

/* public: */
	unsigned int readonly:1;
	unsigned int allow_custom_flags:1;
/* private: */
	unsigned int inconsistent:1;
};

struct _MailboxStatus {
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

struct _MailboxSyncCallbacks {
	/* Alert: Not enough disk space */
	void (*alert_no_diskspace)(Mailbox *mailbox, void *context);

	/* EXPUNGE */
	void (*expunge)(Mailbox *mailbox, unsigned int seq, void *context);
	/* FETCH FLAGS */
	void (*update_flags)(Mailbox *mailbox, unsigned int seq,
			     unsigned int uid, MailFlags flags,
			     const char *custom_flags[],
			     unsigned int custom_flags_count, void *context);

	/* EXISTS, RECENT */
	void (*new_messages)(Mailbox *mailbox, unsigned int messages_count,
			     unsigned int recent_count, void *context);
	/* FLAGS, PERMANENTFLAGS */
	void (*new_custom_flags)(Mailbox *mailbox, const char *custom_flags[],
				 unsigned int custom_flags_count,
				 void *context);

};

struct _MailFetchData {
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

	MailFetchBodyData *body_sections;
};

struct _MailFetchBodyData {
	MailFetchBodyData *next;

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
void mail_storage_class_register(MailStorage *storage_class);
void mail_storage_class_unregister(MailStorage *storage_class);

/* Create a new instance of registered mail storage class with given
   storage-specific data. If data is NULL, it tries to use defaults.
   May return NULL if anything fails. */
MailStorage *mail_storage_create(const char *name, const char *data,
				 const char *user);
void mail_storage_destroy(MailStorage *storage);

MailStorage *mail_storage_create_default(const char *user);
MailStorage *mail_storage_create_with_data(const char *data, const char *user);

/* Set error message in storage. Critical errors are logged with i_error(),
   but user sees only "internal error" message. */
void mail_storage_clear_error(MailStorage *storage);
void mail_storage_set_error(MailStorage *storage, const char *fmt, ...)
	__attr_format__(2, 3);
void mail_storage_set_critical(MailStorage *storage, const char *fmt, ...)
	__attr_format__(2, 3);
void mail_storage_set_internal_error(MailStorage *storage);

const char *mail_storage_get_last_error(MailStorage *storage);
int mail_storage_is_inconsistency_error(Mailbox *box);

#endif
