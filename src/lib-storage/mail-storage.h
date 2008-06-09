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
	/* Print debugging information while initializing the storage */
	MAIL_STORAGE_FLAG_DEBUG			= 0x01,
	/* Allow full filesystem access with absolute or relative paths. */
	MAIL_STORAGE_FLAG_FULL_FS_ACCESS	= 0x02,
	/* Don't try to mmap() files */
	MAIL_STORAGE_FLAG_MMAP_DISABLE		= 0x04,
	/* Don't try to write() to mmap()ed files. Required for the few
	   OSes that don't have unified buffer cache
	   (currently OpenBSD <= 3.5) */
	MAIL_STORAGE_FLAG_MMAP_NO_WRITE		= 0x08,
	/* Remember message headers' MD5 sum */
	MAIL_STORAGE_FLAG_KEEP_HEADER_MD5	= 0x10,
	/* Use CRLF linefeeds when saving mails. */
	MAIL_STORAGE_FLAG_SAVE_CRLF		= 0x40,
	/* Don't try to autodetect anything, require that the given data 
	   contains all the necessary information. */
	MAIL_STORAGE_FLAG_NO_AUTODETECTION	= 0x100,
	/* Don't autocreate any directories. If they don't exist,
	   fail to create the storage. */
	MAIL_STORAGE_FLAG_NO_AUTOCREATE		= 0x200,
	/* Rely on O_EXCL when creating dotlocks */
	MAIL_STORAGE_FLAG_DOTLOCK_USE_EXCL	= 0x400,
	/* Flush NFS caches for mail storage / index */
	MAIL_STORAGE_FLAG_NFS_FLUSH_STORAGE	= 0x800,
	MAIL_STORAGE_FLAG_NFS_FLUSH_INDEX	= 0x1000,
	/* Don't use fsync() or fdatasync() */
	MAIL_STORAGE_FLAG_FSYNC_DISABLE		= 0x2000
};

enum mailbox_open_flags {
	/* Mailbox must not be modified even if asked */
	MAILBOX_OPEN_READONLY		= 0x01,
	/* Only saving/copying mails to mailbox works. */
	MAILBOX_OPEN_SAVEONLY		= 0x02,
	/* Any extra time consuming operations shouldn't be performed
	   (eg. when opening mailbox just for STATUS). */
	MAILBOX_OPEN_FAST		= 0x04,
	/* Don't reset MAIL_RECENT flags when syncing */
	MAILBOX_OPEN_KEEP_RECENT	= 0x08,
	/* Don't create index files for the mailbox */
	MAILBOX_OPEN_NO_INDEX_FILES	= 0x10,
	/* Keep mailbox exclusively locked all the time while it's open */
	MAILBOX_OPEN_KEEP_LOCKED	= 0x20,
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
	STATUS_HIGHESTMODSEQ	= 0x80
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
#define MAX_SORT_PROGRAM_SIZE (7 + 1)

	MAIL_SORT_ARRIVAL	= 0x0001,
	MAIL_SORT_CC		= 0x0002,
	MAIL_SORT_DATE		= 0x0004,
	MAIL_SORT_FROM		= 0x0008,
	MAIL_SORT_SIZE		= 0x0010,
	MAIL_SORT_SUBJECT	= 0x0020,
	MAIL_SORT_TO		= 0x0040,

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
	MAIL_FETCH_UIDL_BACKEND		= 0x00040000
};

enum mailbox_transaction_flags {
	/* Hide changes done in this transaction from next view sync */
	MAILBOX_TRANSACTION_FLAG_HIDE		= 0x01,
	/* External transaction. Should be used for copying and appends,
	   but nothing else. */
	MAILBOX_TRANSACTION_FLAG_EXTERNAL	= 0x02,
	/* Always assign UIDs to messages when saving/copying. Normally this
	   is done only if the mailbox is synced, or if dest_mail parameter
	   was non-NULL to mailbox_save_init() or mailbox_copy() */
	MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS	= 0x04,
	/* Refresh the index so lookups return latest flags/modseqs */
	MAILBOX_TRANSACTION_FLAG_REFRESH	= 0x08
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
	/* Stop auto syncing */
	MAILBOX_SYNC_AUTO_STOP			= 0x20,
	/* If mailbox is currently inconsistent, fix it instead of failing. */
	MAILBOX_SYNC_FLAG_FIX_INCONSISTENT	= 0x40,
	/* Syncing after an EXPUNGE command. This is just an informational
	   flag for plugins. */
	MAILBOX_SYNC_FLAG_EXPUNGE		= 0x80
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
	uint64_t highest_modseq;

	const ARRAY_TYPE(keywords) *keywords;
};

struct mailbox_sync_rec {
	uint32_t seq1, seq2;
	enum mailbox_sync_type type;
};

struct mail {
	/* always set */
	struct mailbox *box;
	struct mailbox_transaction_context *transaction;
	uint32_t seq, uid;

	unsigned int expunged:1;
	unsigned int has_nuls:1; /* message data is known to contain NULs */
	unsigned int has_no_nuls:1; /* -''- known to not contain NULs */
};

struct mail_storage_callbacks {
	/* "* OK <text>" */
	void (*notify_ok)(struct mailbox *mailbox, const char *text,
			  void *context);
	/* "* NO <text>" */
	void (*notify_no)(struct mailbox *mailbox, const char *text,
			  void *context);

};

typedef void mailbox_notify_callback_t(struct mailbox *box, void *context);

void mail_storage_init(void);
void mail_storage_deinit(void);

/* register all mail storages */
void mail_storage_register_all(void);

/* Register mail storage class with given name - all methods that are NULL
   are set to default methods */
void mail_storage_class_register(struct mail_storage *storage_class);
void mail_storage_class_unregister(struct mail_storage *storage_class);

/* Returns flags and lock_method based on environment settings. */
void mail_storage_parse_env(enum mail_storage_flags *flags_r,
			    enum file_lock_method *lock_method_r);

/* Create a new instance of registered mail storage class with given
   storage-specific data. If driver is NULL, it's tried to be autodetected
   from data. If data is NULL, it uses the first storage that exists.
   The storage is put into ns->storage. */
int mail_storage_create(struct mail_namespace *ns, const char *driver,
			const char *data, const char *user,
			enum mail_storage_flags flags,
			enum file_lock_method lock_method,
			const char **error_r);
void mail_storage_destroy(struct mail_storage **storage);

char mail_storage_get_hierarchy_sep(struct mail_storage *storage);
struct mailbox_list *mail_storage_get_list(struct mail_storage *storage);
struct mail_namespace *mail_storage_get_namespace(struct mail_storage *storage);

/* Set storage callback functions to use. */
void mail_storage_set_callbacks(struct mail_storage *storage,
				struct mail_storage_callbacks *callbacks,
				void *context);

/* name is allowed to contain multiple new hierarchy levels.
   If directory is TRUE, the mailbox should be created so that it
   can contain children. The mailbox itself doesn't have to be
   created as long as it shows in LIST. */
int mail_storage_mailbox_create(struct mail_storage *storage, const char *name,
				bool directory);

/* Returns the error message of last occurred error. */
const char *mail_storage_get_last_error(struct mail_storage *storage,
					enum mail_error *error_r);

/* Returns path to the given mailbox, or NULL if mailbox doesn't exist in
   filesystem. is_file_r is set to TRUE if returned path points to a file,
   and FALSE if it points to a directory. If name is "", the root storage
   directory is returned. */
const char *mail_storage_get_mailbox_path(struct mail_storage *storage,
					  const char *name, bool *is_file_r);
/* Returns path to the control directory of the mailbox, or NULL if mailbox
   doesn't exist in filesystem. */
const char *mail_storage_get_mailbox_control_dir(struct mail_storage *storage,
						 const char *name);
/* Returns path to the index directory of the mailbox, or NULL if using
   in-memory indexes or mailbox doesn't exist. */
const char *mail_storage_get_mailbox_index_dir(struct mail_storage *storage,
					       const char *name);

/* Open a mailbox. If input stream is given, mailbox is opened read-only
   using it as a backend. If storage doesn't support stream backends and its
   tried to be used, NULL is returned.

   Note that append and copy may open the selected mailbox again
   with possibly different readonly-state. */
struct mailbox *mailbox_open(struct mail_storage *storage, const char *name,
			     struct istream *input,
			     enum mailbox_open_flags flags);
/* Close the box. Returns -1 if some cleanup errors occurred, but
   the mailbox was closed anyway. */
int mailbox_close(struct mailbox **box);

/* Enable the given feature for the mailbox. */
int mailbox_enable(struct mailbox *box, enum mailbox_feature features);
enum mailbox_feature mailbox_get_enabled_features(struct mailbox *box);

/* Returns storage of given mailbox */
struct mail_storage *mailbox_get_storage(struct mailbox *box);

/* Returns name of given mailbox */
const char *mailbox_get_name(struct mailbox *box);

/* Returns TRUE if mailbox is read-only. */
bool mailbox_is_readonly(struct mailbox *box);

/* Returns TRUE if mailbox currently supports adding keywords. */
bool mailbox_allow_new_keywords(struct mailbox *box);

/* Gets the mailbox status information. */
void mailbox_get_status(struct mailbox *box, enum mailbox_status_items items,
			struct mailbox_status *status_r);

/* Synchronize the mailbox. */
struct mailbox_sync_context *
mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
bool mailbox_sync_next(struct mailbox_sync_context *ctx,
		       struct mailbox_sync_rec *sync_rec_r);
int mailbox_sync_deinit(struct mailbox_sync_context **ctx,
			enum mailbox_status_items status_items,
			struct mailbox_status *status_r);
/* One-step mailbox synchronization. Use this if you don't care about
   changes. */
int mailbox_sync(struct mailbox *box, enum mailbox_sync_flags flags,
		 enum mailbox_status_items status_items,
		 struct mailbox_status *status_r);

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
/* If no messages were saved/copied, first/last_saved_uid_r are 0. */
int mailbox_transaction_commit_get_uids(struct mailbox_transaction_context **t,
					uint32_t *uid_validity_r,
					uint32_t *first_saved_uid_r,
					uint32_t *last_saved_uid_r);
void mailbox_transaction_rollback(struct mailbox_transaction_context **t);
/* Return the number of active transactions for the mailbox. */
unsigned int mailbox_transaction_get_count(struct mailbox *box);

struct mailbox *
mailbox_transaction_get_mailbox(struct mailbox_transaction_context *t);

/* Build mail_keywords from NULL-terminated keywords list.
   Returns 0 if successful, -1 if there are invalid keywords (error is set). */
int mailbox_keywords_create(struct mailbox *box, const char *const keywords[],
			    struct mail_keywords **keywords_r);
/* Like mailbox_keywords_create(), except ignore invalid keywords. */
struct mail_keywords *
mailbox_keywords_create_valid(struct mailbox *box,
			      const char *const keywords[]);
void mailbox_keywords_free(struct mailbox *box,
			   struct mail_keywords **keywords);

/* Convert uid range to sequence range. */
void mailbox_get_seq_range(struct mailbox *box, uint32_t uid1, uint32_t uid2,
			   uint32_t *seq1_r, uint32_t *seq2_r);
/* Convert sequence range to uid range. If sequences contain
   (uint32_t)-1 to specify "*", they're preserved. */
void mailbox_get_uid_range(struct mailbox *box,
			   const ARRAY_TYPE(seq_range) *seqs,
			   ARRAY_TYPE(seq_range) *uids);
/* Get list of UIDs expunged after modseq and within the given range.
   UIDs that have been expunged after the last mailbox sync aren't returned.
   Returns TRUE if ok, FALSE if modseq is lower than we can check for. */
bool mailbox_get_expunged_uids(struct mailbox *box, uint64_t modseq,
			       const ARRAY_TYPE(seq_range) *uids,
			       ARRAY_TYPE(seq_range) *expunged_uids);

/* Initialize header lookup for given headers. */
struct mailbox_header_lookup_ctx *
mailbox_header_lookup_init(struct mailbox *box, const char *const headers[]);
void mailbox_header_lookup_deinit(struct mailbox_header_lookup_ctx **ctx);

/* Initialize new search request. charset specifies the character set used in
   the search argument strings. If sort_program is non-NULL, the messages are
   returned in the requested order, otherwise from first to last. */
struct mail_search_context *
mailbox_search_init(struct mailbox_transaction_context *t,
		    struct mail_search_args *args,
		    const enum mail_sort_type *sort_program);
/* Deinitialize search request. */
int mailbox_search_deinit(struct mail_search_context **ctx);
/* Search the next message. Returns 1 if found, 0 if not, -1 if failure. */
int mailbox_search_next(struct mail_search_context *ctx, struct mail *mail);
/* Like mailbox_search_next(), but don't spend too much time searching.
   Returns 1 if found, -1 if failure or 0 with tryagain_r=FALSE if
   finished, and TRUE if more results will by calling the function again. */
int mailbox_search_next_nonblock(struct mail_search_context *ctx,
				 struct mail *mail, bool *tryagain_r);

/* Remember the search result for future use. This must be called before the
   first mailbox_search_next*() call. */
struct mail_search_result *
mailbox_search_result_save(struct mail_search_context *ctx,
			   enum mailbox_search_result_flags flags);
/* Free memory used by search result. */
void mailbox_search_result_free(struct mail_search_result **result);
/* Return all messages' UIDs in the search result. */
const ARRAY_TYPE(seq_range) *
mailbox_search_result_get(struct mail_search_result *result);
/* Return messages that have been removed and added since the last sync call.
   This function must not be called if search result wasn't saved with
   _QUEUE_SYNC flag. */
void mailbox_search_result_sync(struct mail_search_result *result,
				ARRAY_TYPE(seq_range) *removed_uids,
				ARRAY_TYPE(seq_range) *added_uids);

/* Save a mail into mailbox. timezone_offset specifies the timezone in
   minutes in which received_date was originally given with. To use
   current time, set received_date to (time_t)-1.

   If dest_mail is set, the saved message can be accessed using it. Note that
   setting it may require mailbox syncing, so don't set it unless you need
   it. Also you shouldn't try to access it before mailbox_save_finish() is
   called.

   The given input stream is never read in these functions, only the data
   inside it is used. So you should call i_stream_read() yourself and then
   call mailbox_save_continue() whenever more data is read.
*/
int mailbox_save_init(struct mailbox_transaction_context *t,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      time_t received_date, int timezone_offset,
		      const char *from_envelope, struct istream *input,
		      struct mail *dest_mail, struct mail_save_context **ctx_r);
int mailbox_save_continue(struct mail_save_context *ctx);
int mailbox_save_finish(struct mail_save_context **ctx);
void mailbox_save_cancel(struct mail_save_context **ctx);

/* Copy given message. If dest_mail is non-NULL, the copied message can be
   accessed using it. Note that setting it non-NULL may require mailbox
   syncing, so don't give give it unless you need it. */
int mailbox_copy(struct mailbox_transaction_context *t, struct mail *mail,
		 enum mail_flags flags, struct mail_keywords *keywords,
		 struct mail *dest_mail);

/* Returns TRUE if mailbox is now in inconsistent state, meaning that
   the message IDs etc. may have changed - only way to recover this
   would be to fully close the mailbox and reopen it. With IMAP
   connection this would mean a forced disconnection since we can't
   do forced CLOSE. */
bool mailbox_is_inconsistent(struct mailbox *box);

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
int mail_get_parts(struct mail *mail, const struct message_part **parts_r);

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
/* Like mail_get_first_header(), but decode MIME encoded words to UTF-8 */
int mail_get_first_header_utf8(struct mail *mail, const char *field,
			       const char **value_r);
/* Return a NULL-terminated list of values for each found field. */
int mail_get_headers(struct mail *mail, const char *field,
		     const char *const **value_r);
/* Like mail_get_headers(), but decode MIME encoded words to UTF-8 */
int mail_get_headers_utf8(struct mail *mail, const char *field,
			  const char *const **value_r);
/* Returns stream containing specified headers. */
int mail_get_header_stream(struct mail *mail,
			   struct mailbox_header_lookup_ctx *headers,
			   struct istream **stream_r);
/* Returns input stream pointing to beginning of message header.
   hdr_size and body_size are updated unless they're NULL. */
int mail_get_stream(struct mail *mail, struct message_size *hdr_size,
		    struct message_size *body_size, struct istream **stream_r);

/* Get any of the "special" fields. */
int mail_get_special(struct mail *mail, enum mail_fetch_field field,
		     const char **value_r);

/* Update message flags. */
void mail_update_flags(struct mail *mail, enum modify_type modify_type,
		       enum mail_flags flags);
/* Update message keywords. */
void mail_update_keywords(struct mail *mail, enum modify_type modify_type,
			  struct mail_keywords *keywords);

/* Expunge this message. Sequence numbers don't change until commit. */
void mail_expunge(struct mail *mail);
/* Mark a cached field corrupted and have it recalculated. */
void mail_set_cache_corrupted(struct mail *mail, enum mail_fetch_field field);

#endif
