#ifndef MAIL_STORAGE_H
#define MAIL_STORAGE_H

struct message_size;

#include "seq-range-array.h"
#include "file-lock.h"
#include "mail-types.h"
#include "mail-error.h"
#include "mailbox-list.h"

/* If some operation is taking long, call notify_ok every n seconds. */
#define MAIL_STORAGE_STAYALIVE_SECS 15

enum mail_storage_flags {
	/* Remember message headers' MD5 sum */
	MAIL_STORAGE_FLAG_KEEP_HEADER_MD5	= 0x01,
	/* Don't try to autodetect anything, require that the given data 
	   contains all the necessary information. */
	MAIL_STORAGE_FLAG_NO_AUTODETECTION	= 0x02,
	/* Don't autocreate any directories. If they don't exist,
	   fail to create the storage. */
	MAIL_STORAGE_FLAG_NO_AUTOCREATE		= 0x04,
	/* Don't verify existence or accessibility of any directories.
	   Create the storage in any case. */
	MAIL_STORAGE_FLAG_NO_AUTOVERIFY		= 0x08
};

enum mailbox_flags {
	/* Mailbox must not be modified even if asked */
	MAILBOX_FLAG_READONLY		= 0x01,
	/* Only saving/copying mails to mailbox works. */
	MAILBOX_FLAG_SAVEONLY		= 0x02,
	/* Don't reset MAIL_RECENT flags when syncing */
	MAILBOX_FLAG_KEEP_RECENT	= 0x08,
	/* Don't create index files for the mailbox */
	MAILBOX_FLAG_NO_INDEX_FILES	= 0x10,
	/* Keep mailbox exclusively locked all the time while it's open */
	MAILBOX_FLAG_KEEP_LOCKED	= 0x20,
	/* Enable if mailbox is used for serving POP3. This allows making
	   better caching decisions. */
	MAILBOX_FLAG_POP3_SESSION	= 0x40,
	/* Enable if mailbox is used for saving a mail delivery using MDA.
	   This causes ACL plugin to use POST right rather than INSERT. */
	MAILBOX_FLAG_POST_SESSION	= 0x80,
	/* Force opening mailbox and ignoring any ACLs */
	MAILBOX_FLAG_IGNORE_ACLS	= 0x100,
	/* Open mailbox even if it's already marked as deleted */
	MAILBOX_FLAG_OPEN_DELETED	= 0x200
};

enum mailbox_feature {
	/* Enable tracking modsequences */
	MAILBOX_FEATURE_CONDSTORE	= 0x01,
	/* Enable tracking expunge modsequences */
	MAILBOX_FEATURE_QRESYNC		= 0x02
};

enum mailbox_status_items {
	STATUS_MESSAGES		= 0x01,
	STATUS_RECENT		= 0x02,
	STATUS_UIDNEXT		= 0x04,
	STATUS_UIDVALIDITY	= 0x08,
	STATUS_UNSEEN		= 0x10,
	STATUS_FIRST_UNSEEN_SEQ	= 0x20,
	STATUS_KEYWORDS		= 0x40,
	STATUS_HIGHESTMODSEQ	= 0x80,
	STATUS_CACHE_FIELDS	= 0x100,
	STATUS_VIRTUAL_SIZE	= 0x200,
	STATUS_FIRST_RECENT_UID	= 0x400
};

enum mailbox_search_result_flags {
	/* Update search results whenever the mailbox view is synced.
	   Expunged messages are removed even without this flag. */
	MAILBOX_SEARCH_RESULT_FLAG_UPDATE	= 0x01,
	/* Queue changes so _sync() can be used. */
	MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC	= 0x02
};

enum mail_sort_type {
/* Maximum size for sort program (each one separately + END) */
#define MAX_SORT_PROGRAM_SIZE (8 + 1)

	MAIL_SORT_ARRIVAL	= 0x0001,
	MAIL_SORT_CC		= 0x0002,
	MAIL_SORT_DATE		= 0x0004,
	MAIL_SORT_FROM		= 0x0008,
	MAIL_SORT_SIZE		= 0x0010,
	MAIL_SORT_SUBJECT	= 0x0020,
	MAIL_SORT_TO		= 0x0040,
	MAIL_SORT_SEARCH_SCORE	= 0x0080,
	MAIL_SORT_DISPLAYFROM	= 0x0100,
	MAIL_SORT_DISPLAYTO	= 0x0200,
	MAIL_SORT_POP3_ORDER	= 0x0400,

	MAIL_SORT_MASK		= 0x0fff,
	MAIL_SORT_FLAG_REVERSE	= 0x1000, /* reverse this mask type */

	MAIL_SORT_END		= 0x0000 /* ends sort program */
};

enum mail_fetch_field {
	MAIL_FETCH_FLAGS		= 0x00000001,
	MAIL_FETCH_MESSAGE_PARTS	= 0x00000002,

	MAIL_FETCH_STREAM_HEADER	= 0x00000004,
	MAIL_FETCH_STREAM_BODY		= 0x00000008,

	MAIL_FETCH_DATE			= 0x00000010,
	MAIL_FETCH_RECEIVED_DATE	= 0x00000020,
	MAIL_FETCH_SAVE_DATE		= 0x00000040,
	MAIL_FETCH_PHYSICAL_SIZE	= 0x00000080,
	MAIL_FETCH_VIRTUAL_SIZE		= 0x00000100,

	/* Set has_nuls / has_no_nuls fields */
	MAIL_FETCH_NUL_STATE		= 0x00000200,

	/* specials: */
	MAIL_FETCH_IMAP_BODY		= 0x00001000,
	MAIL_FETCH_IMAP_BODYSTRUCTURE	= 0x00002000,
	MAIL_FETCH_IMAP_ENVELOPE	= 0x00004000,
	MAIL_FETCH_FROM_ENVELOPE	= 0x00008000,
	MAIL_FETCH_HEADER_MD5		= 0x00010000,
	MAIL_FETCH_UIDL_FILE_NAME	= 0x00020000,
	MAIL_FETCH_UIDL_BACKEND		= 0x00040000,
	MAIL_FETCH_MAILBOX_NAME		= 0x00080000,
	MAIL_FETCH_SEARCH_SCORE		= 0x00100000,
	MAIL_FETCH_GUID			= 0x00200000,
	MAIL_FETCH_POP3_ORDER		= 0x00400000
};

enum mailbox_transaction_flags {
	/* Hide changes done in this transaction from next view sync */
	MAILBOX_TRANSACTION_FLAG_HIDE		= 0x01,
	/* External transaction. Should be used for copying and appends,
	   but nothing else. */
	MAILBOX_TRANSACTION_FLAG_EXTERNAL	= 0x02,
	/* Always assign UIDs to messages when saving/copying. Normally this
	   is done only if it can be done easily. */
	MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS	= 0x04,
	/* Refresh the index so lookups return latest flags/modseqs */
	MAILBOX_TRANSACTION_FLAG_REFRESH	= 0x08,
	/* Don't update caching decisions no matter what we do in this
	   transaction (useful for e.g. precaching) */
	MAILBOX_TRANSACTION_FLAG_NO_CACHE_DEC	= 0x10
};

enum mailbox_sync_flags {
	/* Make sure we sync all external changes done to mailbox */
	MAILBOX_SYNC_FLAG_FULL_READ		= 0x01,
	/* Make sure we write all our internal changes into the mailbox */
	MAILBOX_SYNC_FLAG_FULL_WRITE		= 0x02,
	/* If it's not too much trouble, check if there are some changes */
	MAILBOX_SYNC_FLAG_FAST			= 0x04,

	/* Don't sync expunges from our view */
	MAILBOX_SYNC_FLAG_NO_EXPUNGES		= 0x08,
	/* If mailbox is currently inconsistent, fix it instead of failing. */
	MAILBOX_SYNC_FLAG_FIX_INCONSISTENT	= 0x40,
	/* Syncing after an EXPUNGE command. This is just an informational
	   flag for plugins. */
	MAILBOX_SYNC_FLAG_EXPUNGE		= 0x80,
	/* Force doing a full resync of indexes. */
	MAILBOX_SYNC_FLAG_FORCE_RESYNC		= 0x100,
	/* Add all missing data to cache and fts index ("doveadm index") */
	MAILBOX_SYNC_FLAG_PRECACHE		= 0x200
};

enum mailbox_sync_type {
	MAILBOX_SYNC_TYPE_EXPUNGE	= 0x01,
	MAILBOX_SYNC_TYPE_FLAGS		= 0x02,
	MAILBOX_SYNC_TYPE_MODSEQ	= 0x04
};

struct message_part;
struct mail_namespace;
struct mail_storage;
struct mail_search_args;
struct mail_search_result;
struct mail_keywords;
struct mail_save_context;
struct mailbox;
struct mailbox_transaction_context;

struct mailbox_status {
	uint32_t messages;
	uint32_t recent;
	uint32_t unseen;

	uint32_t uidvalidity;
	uint32_t uidnext;

	uint32_t first_unseen_seq;
	uint32_t first_recent_uid;
	uint64_t highest_modseq;
	/* sum of virtual size of all messages in mailbox */
	uint64_t virtual_size;

	const ARRAY_TYPE(keywords) *keywords;
	/* Fields that have "temp" or "yes" caching decision. */
	const ARRAY_TYPE(const_string) *cache_fields;

	/* Modseqs aren't permanent (index is in memory) */
	unsigned int nonpermanent_modseqs:1;
};

struct mailbox_update {
	/* All non-zero fields are changed. */
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
	uint32_t uid_validity;
	uint32_t min_next_uid;
	uint32_t min_first_recent_uid;
	uint64_t min_highest_modseq;
	/* Add these fields to be temporarily cached, if they aren't already. */
	const char *const *cache_fields;
};

struct mail_transaction_commit_changes {
	/* Unreference the pool to free memory used by these changes. */
	pool_t pool;

	/* UIDVALIDITY for assigned UIDs. */
	uint32_t uid_validity;
	/* UIDs assigned to saved messages. Not necessarily ascending. */
	ARRAY_TYPE(seq_range) saved_uids;

	/* number of modseq changes that couldn't be changed as requested */
	unsigned int ignored_modseq_changes;
};

struct mailbox_sync_rec {
	uint32_t seq1, seq2;
	enum mailbox_sync_type type;
};
struct mailbox_sync_status {
	/* There are expunges that haven't been synced yet */
	unsigned int sync_delayed_expunges:1;
};

struct mailbox_expunge_rec {
	/* IMAP UID */
	uint32_t uid;
	/* 128 bit GUID. If the actual GUID has a different size, this
	   contains last bits of its SHA1 sum. */
	uint8_t guid_128[MAIL_GUID_128_SIZE];
};
ARRAY_DEFINE_TYPE(mailbox_expunge_rec, struct mailbox_expunge_rec);

enum mail_lookup_abort {
	/* Perform everything no matter what it takes */
	MAIL_LOOKUP_ABORT_NEVER = 0,
	/* Abort if the operation would require reading message header/body */
	MAIL_LOOKUP_ABORT_READ_MAIL,
	/* Abort if the operation can't be done fully using cache file */
	MAIL_LOOKUP_ABORT_NOT_IN_CACHE
};

struct mail {
	/* always set */
	struct mailbox *box;
	struct mailbox_transaction_context *transaction;
	uint32_t seq, uid;

	unsigned int expunged:1;
	unsigned int saving:1; /* This mail is still being saved */
	unsigned int has_nuls:1; /* message data is known to contain NULs */
	unsigned int has_no_nuls:1; /* -''- known to not contain NULs */

	/* If the lookup is aborted, error is set to MAIL_ERROR_NOTPOSSIBLE */
	enum mail_lookup_abort lookup_abort;
};

struct mail_storage_callbacks {
	/* "* OK <text>" */
	void (*notify_ok)(struct mailbox *mailbox, const char *text,
			  void *context);
	/* "* NO <text>" */
	void (*notify_no)(struct mailbox *mailbox, const char *text,
			  void *context);

};

struct mailbox_virtual_pattern {
	struct mail_namespace *ns;
	const char *pattern;
};
ARRAY_DEFINE_TYPE(mailbox_virtual_patterns, struct mailbox_virtual_pattern);
ARRAY_DEFINE_TYPE(mail_storage, struct mail_storage *);
ARRAY_DEFINE_TYPE(mailboxes, struct mailbox *);

extern ARRAY_TYPE(mail_storage) mail_storage_classes;

typedef void mailbox_notify_callback_t(struct mailbox *box, void *context);

void mail_storage_init(void);
void mail_storage_deinit(void);

/* register all mail storages */
void mail_storage_register_all(void);

/* Register mail storage class with given name - all methods that are NULL
   are set to default methods */
void mail_storage_class_register(struct mail_storage *storage_class);
void mail_storage_class_unregister(struct mail_storage *storage_class);
/* Find mail storage class by name */
struct mail_storage *mail_storage_find_class(const char *name);

/* Create a new instance of registered mail storage class with given
   storage-specific data. If driver is NULL, it's tried to be autodetected
   from ns location. If ns location is NULL, it uses the first storage that
   exists. The storage is put into ns->storage. */
int mail_storage_create(struct mail_namespace *ns, const char *driver,
			enum mail_storage_flags flags, const char **error_r);
void mail_storage_unref(struct mail_storage **storage);

/* Returns the mail storage settings. */
const struct mail_storage_settings *
mail_storage_get_settings(struct mail_storage *storage) ATTR_PURE;
struct mail_user *mail_storage_get_user(struct mail_storage *storage) ATTR_PURE;

/* Set storage callback functions to use. */
void mail_storage_set_callbacks(struct mail_storage *storage,
				struct mail_storage_callbacks *callbacks,
				void *context);

/* Purge storage's mailboxes (freeing disk space from expunged mails),
   if supported by the storage. Otherwise just a no-op. */
int mail_storage_purge(struct mail_storage *storage);

/* Returns the error message of last occurred error. */
const char *mail_storage_get_last_error(struct mail_storage *storage,
					enum mail_error *error_r);

/* Returns TRUE if mailboxes are files. */
bool mail_storage_is_mailbox_file(struct mail_storage *storage) ATTR_PURE;

/* Initialize mailbox without actually opening any files or verifying that
   it exists. Note that append and copy may open the selected mailbox again
   with possibly different readonly-state. */
struct mailbox *mailbox_alloc(struct mailbox_list *list, const char *name,
			      enum mailbox_flags flags);
/* Open the mailbox. If this function isn't called explicitly, it's also called
   internally by lib-storage when necessary. */
int mailbox_open(struct mailbox *box);
/* Open mailbox as read-only using the given stream as input. */
int mailbox_open_stream(struct mailbox *box, struct istream *input);
/* Close mailbox. Same as if mailbox was freed and re-allocated. */
void mailbox_close(struct mailbox *box);
/* Close and free the mailbox. */
void mailbox_free(struct mailbox **box);

/* Create a mailbox. Returns failure if it already exists. Mailbox name is
   allowed to contain multiple new nonexistent hierarchy levels. If directory
   is TRUE, the mailbox should be created so that it can contain children. The
   mailbox itself doesn't have to be created as long as it shows up in LIST.
   If update is non-NULL, its contents are used to set initial mailbox
   metadata. */
int mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		   bool directory);
/* Update existing mailbox's metadata. */
int mailbox_update(struct mailbox *box, const struct mailbox_update *update);
/* Delete mailbox (and its parent directory, if it has no siblings) */
int mailbox_delete(struct mailbox *box);
/* Rename mailbox. Renaming across different mailbox lists is possible only
   between private namespaces and storages of the same type. If the rename
   fails, the error is set to src's storage. */
int mailbox_rename(struct mailbox *src, struct mailbox *dest,
		   bool rename_children);

/* Enable the given feature for the mailbox. */
int mailbox_enable(struct mailbox *box, enum mailbox_feature features);
/* Returns all enabled features. */
enum mailbox_feature
mailbox_get_enabled_features(struct mailbox *box) ATTR_PURE;

/* Returns storage of given mailbox */
struct mail_storage *mailbox_get_storage(const struct mailbox *box) ATTR_PURE;
/* Return namespace of given mailbox. */
struct mail_namespace *
mailbox_get_namespace(const struct mailbox *box) ATTR_PURE;
/* Returns the storage's settings. */
const struct mail_storage_settings *
mailbox_get_settings(struct mailbox *box) ATTR_PURE;

/* Returns name of given mailbox */
const char *mailbox_get_name(const struct mailbox *box) ATTR_PURE;
/* Returns the virtual name of the given mailbox. This is the same as using
   mail_namespace_get_vname(). */
const char *mailbox_get_vname(const struct mailbox *box) ATTR_PURE;

/* Returns TRUE if mailbox is read-only. */
bool mailbox_is_readonly(struct mailbox *box);
/* Returns TRUE if mailbox currently supports adding keywords. */
bool mailbox_allow_new_keywords(struct mailbox *box);
/* Returns TRUE if two mailboxes point to the same physical mailbox. */
bool mailbox_backends_equal(const struct mailbox *box1,
			    const struct mailbox *box2);
/* Returns TRUE if mailbox is now in inconsistent state, meaning that
   the message IDs etc. may have changed - only way to recover this
   would be to fully close the mailbox and reopen it. With IMAP
   connection this would mean a forced disconnection since we can't
   do forced CLOSE. */
bool mailbox_is_inconsistent(struct mailbox *box);

/* Gets the mailbox status information. */
void mailbox_get_status(struct mailbox *box, enum mailbox_status_items items,
			struct mailbox_status *status_r);
/* Get mailbox GUID, creating it if necessary. */
int mailbox_get_guid(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE]);

/* Synchronize the mailbox. */
struct mailbox_sync_context *
mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
bool mailbox_sync_next(struct mailbox_sync_context *ctx,
		       struct mailbox_sync_rec *sync_rec_r);
int mailbox_sync_deinit(struct mailbox_sync_context **ctx,
			struct mailbox_sync_status *status_r);
/* One-step mailbox synchronization. Use this if you don't care about
   changes. */
int mailbox_sync(struct mailbox *box, enum mailbox_sync_flags flags);

/* Call given callback function when something changes in the mailbox. */
void mailbox_notify_changes(struct mailbox *box, unsigned int min_interval,
			    mailbox_notify_callback_t *callback, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define mailbox_notify_changes(box, min_interval, callback, context) \
	({(void)(1 ? 0 : callback((struct mailbox *)NULL, context)); \
	  mailbox_notify_changes(box, min_interval, \
		(mailbox_notify_callback_t *)callback, context); })
#else
#  define mailbox_notify_changes(box, min_interval, callback, context) \
	  mailbox_notify_changes(box, min_interval, \
		(mailbox_notify_callback_t *)callback, context)
#endif
void mailbox_notify_changes_stop(struct mailbox *box);

struct mailbox_transaction_context *
mailbox_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags);
int mailbox_transaction_commit(struct mailbox_transaction_context **t);
int mailbox_transaction_commit_get_changes(
	struct mailbox_transaction_context **t,
	struct mail_transaction_commit_changes *changes_r);
void mailbox_transaction_rollback(struct mailbox_transaction_context **t);
/* Return the number of active transactions for the mailbox. */
unsigned int mailbox_transaction_get_count(const struct mailbox *box) ATTR_PURE;
/* When committing transaction, drop flag/keyword updates for messages whose
   modseq is larger than max_modseq. Save those messages' sequences to the
   given array. */
void mailbox_transaction_set_max_modseq(struct mailbox_transaction_context *t,
					uint64_t max_modseq,
					ARRAY_TYPE(seq_range) *seqs);

struct mailbox *
mailbox_transaction_get_mailbox(const struct mailbox_transaction_context *t)
	ATTR_PURE;

/* Convert uid range to sequence range. */
void mailbox_get_seq_range(struct mailbox *box, uint32_t uid1, uint32_t uid2,
			   uint32_t *seq1_r, uint32_t *seq2_r);
/* Convert sequence range to uid range. If sequences contain
   (uint32_t)-1 to specify "*", they're preserved. */
void mailbox_get_uid_range(struct mailbox *box,
			   const ARRAY_TYPE(seq_range) *seqs,
			   ARRAY_TYPE(seq_range) *uids);
/* Get list of messages' that have been expunged after prev_modseq and that
   exist in uids_filter range. UIDs that have been expunged after the last
   mailbox sync aren't returned. Returns TRUE if ok, FALSE if modseq is lower
   than we can check for (but expunged_uids is still set as best as it can). */
bool mailbox_get_expunges(struct mailbox *box, uint64_t prev_modseq,
			  const ARRAY_TYPE(seq_range) *uids_filter,
			  ARRAY_TYPE(mailbox_expunge_rec) *expunges);
/* Same as mailbox_get_expunges(), but return only list of UIDs. Not caring
   about GUIDs is slightly faster. */
bool mailbox_get_expunged_uids(struct mailbox *box, uint64_t prev_modseq,
			       const ARRAY_TYPE(seq_range) *uids_filter,
			       ARRAY_TYPE(seq_range) *expunged_uids);
/* If box is a virtual mailbox, look up UID for the given backend message.
   Returns TRUE if found, FALSE if not. */
bool mailbox_get_virtual_uid(struct mailbox *box, const char *backend_mailbox,
			     uint32_t backend_uidvalidity,
			     uint32_t backend_uid, uint32_t *uid_r);
/* If box is a virtual mailbox, return all backend mailboxes. If
   only_with_msgs=TRUE, return only those mailboxes that have at least one
   message existing in the virtual mailbox. */
void mailbox_get_virtual_backend_boxes(struct mailbox *box,
				       ARRAY_TYPE(mailboxes) *mailboxes,
				       bool only_with_msgs);
/* If mailbox is a virtual mailbox, return all mailbox list patterns that
   are used to figure out which mailboxes belong to the virtual mailbox. */
void mailbox_get_virtual_box_patterns(struct mailbox *box,
				ARRAY_TYPE(mailbox_virtual_patterns) *includes,
				ARRAY_TYPE(mailbox_virtual_patterns) *excludes);

/* Initialize new search request. charset specifies the character set used in
   the search argument strings. If sort_program is non-NULL, the messages are
   returned in the requested order, otherwise from first to last. */
struct mail_search_context *
mailbox_search_init(struct mailbox_transaction_context *t,
		    struct mail_search_args *args,
		    const enum mail_sort_type *sort_program);
/* Deinitialize search request. */
int mailbox_search_deinit(struct mail_search_context **ctx);
/* Search the next message. Returns TRUE if found, FALSE if not. */
bool mailbox_search_next(struct mail_search_context *ctx, struct mail *mail);
/* Like mailbox_search_next(), but don't spend too much time searching.
   Returns FALSE with tryagain_r=FALSE if finished, and tryagain_r=TRUE if
   more results will be returned by calling the function again. */
bool mailbox_search_next_nonblock(struct mail_search_context *ctx,
				 struct mail *mail, bool *tryagain_r);
/* Returns TRUE if some messages were already expunged and we couldn't
   determine correctly if those messages should have been returned in this
   search. */
bool mailbox_search_seen_lost_data(struct mail_search_context *ctx);

/* Remember the search result for future use. This must be called before the
   first mailbox_search_next*() call. */
struct mail_search_result *
mailbox_search_result_save(struct mail_search_context *ctx,
			   enum mailbox_search_result_flags flags);
/* Free memory used by search result. */
void mailbox_search_result_free(struct mail_search_result **result);
/* A simplified API for searching and saving the result. */
int mailbox_search_result_build(struct mailbox_transaction_context *t,
				struct mail_search_args *args,
				enum mailbox_search_result_flags flags,
				struct mail_search_result **result_r);
/* Return all messages' UIDs in the search result. */
const ARRAY_TYPE(seq_range) *
mailbox_search_result_get(struct mail_search_result *result);
/* Return messages that have been removed and added since the last sync call.
   This function must not be called if search result wasn't saved with
   _QUEUE_SYNC flag. */
void mailbox_search_result_sync(struct mail_search_result *result,
				ARRAY_TYPE(seq_range) *removed_uids,
				ARRAY_TYPE(seq_range) *added_uids);

/* Build mail_keywords from NULL-terminated keywords list.
   Returns 0 if successful, -1 if there are invalid keywords (error is set). */
int mailbox_keywords_create(struct mailbox *box, const char *const keywords[],
			    struct mail_keywords **keywords_r);
/* Like mailbox_keywords_create(), except ignore invalid keywords. */
struct mail_keywords *
mailbox_keywords_create_valid(struct mailbox *box,
			      const char *const keywords[]);
struct mail_keywords *
mailbox_keywords_create_from_indexes(struct mailbox *box,
				     const ARRAY_TYPE(keyword_indexes) *idx);
void mailbox_keywords_ref(struct mailbox *box, struct mail_keywords *keywords);
void mailbox_keywords_unref(struct mailbox *box,
			    struct mail_keywords **keywords);
/* Returns TRUE if keyword is valid, FALSE and error if not. */
bool mailbox_keyword_is_valid(struct mailbox *box, const char *keyword,
			      const char **error_r);

/* Initialize saving a new mail. You must not try to save more than one mail
   at a time. */
struct mail_save_context *
mailbox_save_alloc(struct mailbox_transaction_context *t);
/* Set the flags and keywords. Nothing is set by default. */
void mailbox_save_set_flags(struct mail_save_context *ctx,
			    enum mail_flags flags,
			    struct mail_keywords *keywords);
/* Copy flags and keywords from given mail. */
void mailbox_save_copy_flags(struct mail_save_context *ctx, struct mail *mail);
/* Set message's modseq to be at least min_modseq. */
void mailbox_save_set_min_modseq(struct mail_save_context *ctx,
				 uint64_t min_modseq);
/* If received date isn't specified the current time is used. timezone_offset
   specifies the preferred timezone in minutes, but it may be ignored if
   backend doesn't support storing it. */
void mailbox_save_set_received_date(struct mail_save_context *ctx,
				    time_t received_date, int timezone_offset);
/* Set the "message saved" date. This should be set only when you're
   replicating/restoring an existing mailbox. */
void mailbox_save_set_save_date(struct mail_save_context *ctx,
				time_t save_date);
/* Set the envelope sender. This is currently used only with mbox files to
   specify the address in From_-line. */
void mailbox_save_set_from_envelope(struct mail_save_context *ctx,
				    const char *envelope);
/* Set message's UID. If UID is smaller than the current next_uid, it's given
   a new UID anyway. */
void mailbox_save_set_uid(struct mail_save_context *ctx, uint32_t uid);
/* Set globally unique ID for the saved mail. A new GUID is generated by
   default. This function should usually be called only when copying an
   existing mail (or restoring a mail from backup). */
void mailbox_save_set_guid(struct mail_save_context *ctx, const char *guid);
/* Set message's POP3 UIDL, if the backend supports it. */
void mailbox_save_set_pop3_uidl(struct mail_save_context *ctx,
				const char *uidl);
/* If dest_mail is set, the saved message can be accessed using it. Note that
   setting it may require mailbox syncing, so don't set it unless you need
   it. Also you shouldn't try to access it before mailbox_save_finish() is
   called. */
void mailbox_save_set_dest_mail(struct mail_save_context *ctx,
				struct mail *mail);
/* Begin saving the message. All mail_save_set_*() calls must have been called
   before this function. If the save initialization fails, the context is freed
   and -1 is returned. After beginning the save you should keep calling
   i_stream_read() and calling mailbox_save_continue() as long as there's
   more input. */
int mailbox_save_begin(struct mail_save_context **ctx, struct istream *input);
int mailbox_save_continue(struct mail_save_context *ctx);
int mailbox_save_finish(struct mail_save_context **ctx);
void mailbox_save_cancel(struct mail_save_context **ctx);

struct mailbox_transaction_context *
mailbox_save_get_transaction(struct mail_save_context *ctx);

/* Copy the given message. You'll need to specify the flags etc. using the
   mailbox_save_*() functions. */
int mailbox_copy(struct mail_save_context **ctx, struct mail *mail);

/* Initialize header lookup for given headers. */
struct mailbox_header_lookup_ctx *
mailbox_header_lookup_init(struct mailbox *box, const char *const headers[]);
void mailbox_header_lookup_ref(struct mailbox_header_lookup_ctx *ctx);
void mailbox_header_lookup_unref(struct mailbox_header_lookup_ctx **ctx);

struct mail *mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers);
void mail_free(struct mail **mail);
void mail_set_seq(struct mail *mail, uint32_t seq);
/* Returns TRUE if successful, FALSE if message doesn't exist.
   mail_*() functions shouldn't be called if FALSE is returned. */
bool mail_set_uid(struct mail *mail, uint32_t uid);

/* Returns message's flags */
enum mail_flags mail_get_flags(struct mail *mail);
/* Returns message's keywords */
const char *const *mail_get_keywords(struct mail *mail);
/* Returns message's keywords */
const ARRAY_TYPE(keyword_indexes) *mail_get_keyword_indexes(struct mail *mail);
/* Returns message's modseq */
uint64_t mail_get_modseq(struct mail *mail);

/* Returns message's MIME parts */
int mail_get_parts(struct mail *mail, struct message_part **parts_r);

/* Get the Date-header of the mail. Timezone is in minutes. date=0 if it
   wasn't found or it was invalid. */
int mail_get_date(struct mail *mail, time_t *date_r, int *timezone_r);
/* Get the time when the mail was received (IMAP INTERNALDATE). */
int mail_get_received_date(struct mail *mail, time_t *date_r);
/* Get the time when the mail was saved into this mailbox. This time may not
   always be entirely reliable. */
int mail_get_save_date(struct mail *mail, time_t *date_r);

/* Get the space used by the mail as seen by the reader. Linefeeds are always
   counted as being CR+LF. */
int mail_get_virtual_size(struct mail *mail, uoff_t *size_r);
/* Get the size of the stream returned by mail_get_stream(). */
int mail_get_physical_size(struct mail *mail, uoff_t *size_r);

/* Get value for single header field, or NULL if header wasn't found.
   Returns 1 if header was found, 0 if not, -1 if error. */
int mail_get_first_header(struct mail *mail, const char *field,
			  const char **value_r);
/* Like mail_get_first_header(), but decode MIME encoded words to UTF-8.
   Also multiline headers are returned unfolded.

   Do not use this function for getting structured fields (e.g. address fields),
   because decoding may break the structuring. Instead parse them first and
   only afterwards decode the encoded words. */
int mail_get_first_header_utf8(struct mail *mail, const char *field,
			       const char **value_r);
/* Return a NULL-terminated list of values for each found field.
   Returns -1 if error, 0 otherwise (with or without headers found). */
int mail_get_headers(struct mail *mail, const char *field,
		     const char *const **value_r);
/* Like mail_get_headers(), but decode MIME encoded words to UTF-8.
   Also multiline headers are returned unfolded.
   Do not use for structured fields (see mail_get_first_header_utf8()). */
int mail_get_headers_utf8(struct mail *mail, const char *field,
			  const char *const **value_r);
/* Returns stream containing specified headers. */
int mail_get_header_stream(struct mail *mail,
			   struct mailbox_header_lookup_ctx *headers,
			   struct istream **stream_r);
/* Returns input stream pointing to beginning of message header.
   hdr_size and body_size are updated unless they're NULL. The returned stream
   is destroyed automatically, don't unreference it. */
int mail_get_stream(struct mail *mail, struct message_size *hdr_size,
		    struct message_size *body_size, struct istream **stream_r);

/* Get any of the "special" fields. Unhandled specials are returned as "". */
int mail_get_special(struct mail *mail, enum mail_fetch_field field,
		     const char **value_r);
/* Returns the mail for the physical message. Normally this is the mail itself,
   but in virtual mailboxes it points to the backend mailbox. */
struct mail *mail_get_real_mail(struct mail *mail);

/* Update message flags. */
void mail_update_flags(struct mail *mail, enum modify_type modify_type,
		       enum mail_flags flags);
/* Update message keywords. */
void mail_update_keywords(struct mail *mail, enum modify_type modify_type,
			  struct mail_keywords *keywords);
/* Update message's modseq to be at least min_modseq. */
void mail_update_modseq(struct mail *mail, uint64_t min_modseq);

/* Update message's POP3 UIDL (if possible). */
void mail_update_pop3_uidl(struct mail *mail, const char *uidl);
/* Expunge this message. Sequence numbers don't change until commit. */
void mail_expunge(struct mail *mail);

/* Returns TRUE if anything is cached for the mail, FALSE if not. */
bool mail_is_cached(struct mail *mail);
/* Parse mail's header and optionally body so that fields using them get
   cached. */
void mail_parse(struct mail *mail, bool parse_body);
/* Mark a cached field corrupted and have it recalculated. */
void mail_set_cache_corrupted(struct mail *mail, enum mail_fetch_field field);

/* Generate a GUID (contains host name) */
const char *mail_generate_guid_string(void);
/* Generate 128 bit GUID */
void mail_generate_guid_128(uint8_t guid[MAIL_GUID_128_SIZE]);
/* Return 128 bit GUID using input string. If guid is already 128 bit hex
   encoded, it's returned as-is. Otherwise SHA1 sum is taken and its last
   128 bits are returned. */
void mail_generate_guid_128_hash(const char *guid,
				 uint8_t guid_128[MAIL_GUID_128_SIZE]);
/* Returns TRUE if GUID is empty (not set / unknown). */
bool mail_guid_128_is_empty(const uint8_t guid_128[MAIL_GUID_128_SIZE]);
/* Returns GUID as a hex string. */
const char *mail_guid_128_to_string(const uint8_t guid_128[MAIL_GUID_128_SIZE]);

#endif
