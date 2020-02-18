#ifndef MAIL_STORAGE_H
#define MAIL_STORAGE_H

struct message_size;

#include "seq-range-array.h"
#include "file-lock.h"
#include "guid.h"
#include "mail-types.h"
#include "mail-error.h"
#include "mail-index.h"
#include "mail-namespace.h"
#include "mailbox-list.h"
#include "mailbox-attribute.h"

/* If some operation is taking long, call notify_ok every n seconds. */
#define MAIL_STORAGE_STAYALIVE_SECS 15

#define MAIL_KEYWORD_HAS_ATTACHMENT "$HasAttachment"
#define MAIL_KEYWORD_HAS_NO_ATTACHMENT "$HasNoAttachment"

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
	/* Remove MAIL_RECENT flags when syncing */
	MAILBOX_FLAG_DROP_RECENT	= 0x04,
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
	MAILBOX_FLAG_OPEN_DELETED	= 0x200,
	/* Mailbox is opened for deletion, which should be performed as
	   efficiently as possible, even allowing the mailbox state to become
	   inconsistent. For example this disables lazy_expunge plugin and
	   quota updates (possibly resulting in broken quota). and This is
	   useful for example when deleting entire user accounts. */
	MAILBOX_FLAG_DELETE_UNSAFE	= 0x400,
	/* Mailbox is created implicitly if it does not exist. */
	MAILBOX_FLAG_AUTO_CREATE	= 0x1000,
	/* Mailbox is subscribed to implicitly when it is created automatically */
	MAILBOX_FLAG_AUTO_SUBSCRIBE	= 0x2000,
	/* Run fsck for mailbox index before doing anything else. This may be
	   useful in fixing index corruption errors that aren't otherwise
	   detected and that are causing the full mailbox opening to fail. */
	MAILBOX_FLAG_FSCK		= 0x4000,
	/* Interpret name argument for mailbox_alloc_for_user() as a SPECIAL-USE
	   flag. */
	MAILBOX_FLAG_SPECIAL_USE	= 0x8000,
	/* Mailbox is opened for reading/writing attributes. This allows ACL
	   plugin to determine correctly whether the mailbox should be allowed
	   to be opened. */
	MAILBOX_FLAG_ATTRIBUTE_SESSION	= 0x10000,
};

enum mailbox_feature {
	/* Enable tracking modsequences */
	MAILBOX_FEATURE_CONDSTORE	= 0x01,
};

enum mailbox_existence {
	MAILBOX_EXISTENCE_NONE,
	MAILBOX_EXISTENCE_NOSELECT,
	MAILBOX_EXISTENCE_SELECT
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
	STATUS_PERMANENT_FLAGS	= 0x200,
	STATUS_FIRST_RECENT_UID	= 0x400,
	STATUS_LAST_CACHED_SEQ	= 0x800,
	STATUS_CHECK_OVER_QUOTA	= 0x1000, /* return error if over quota */
	STATUS_HIGHESTPVTMODSEQ	= 0x2000,
	/* status items that must not be looked up with
	   mailbox_get_open_status(), because they can return failure. */
#define MAILBOX_STATUS_FAILING_ITEMS \
	(STATUS_LAST_CACHED_SEQ | STATUS_CHECK_OVER_QUOTA)
};

enum mailbox_metadata_items {
	MAILBOX_METADATA_GUID			= 0x01,
	MAILBOX_METADATA_VIRTUAL_SIZE		= 0x02,
	MAILBOX_METADATA_CACHE_FIELDS		= 0x04,
	MAILBOX_METADATA_PRECACHE_FIELDS	= 0x08,
	MAILBOX_METADATA_BACKEND_NAMESPACE	= 0x10,
	MAILBOX_METADATA_PHYSICAL_SIZE		= 0x20,
	MAILBOX_METADATA_FIRST_SAVE_DATE	= 0x40
	/* metadata items that require mailbox to be synced at least once. */
#define MAILBOX_METADATA_SYNC_ITEMS \
	(MAILBOX_METADATA_VIRTUAL_SIZE | MAILBOX_METADATA_PHYSICAL_SIZE | \
	 MAILBOX_METADATA_FIRST_SAVE_DATE)
};

enum mailbox_search_result_flags {
	/* Update search results whenever the mailbox view is synced.
	   Expunged messages are removed even without this flag. */
	MAILBOX_SEARCH_RESULT_FLAG_UPDATE	= 0x01,
	/* Queue changes so _sync() can be used. */
	MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC	= 0x02
};

enum mail_sort_type {
	MAIL_SORT_ARRIVAL	= 0x0001,
	MAIL_SORT_CC		= 0x0002,
	MAIL_SORT_DATE		= 0x0004,
	MAIL_SORT_FROM		= 0x0008,
	MAIL_SORT_SIZE		= 0x0010,
	MAIL_SORT_SUBJECT	= 0x0020,
	MAIL_SORT_TO		= 0x0040,
	MAIL_SORT_RELEVANCY	= 0x0080,
	MAIL_SORT_DISPLAYFROM	= 0x0100,
	MAIL_SORT_DISPLAYTO	= 0x0200,
	MAIL_SORT_POP3_ORDER	= 0x0400,
/* Maximum size for sort program (each one separately + END) */
#define MAX_SORT_PROGRAM_SIZE (11 + 1)

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

	MAIL_FETCH_STREAM_BINARY	= 0x00000400,

	/* specials: */
	MAIL_FETCH_IMAP_BODY		= 0x00001000,
	MAIL_FETCH_IMAP_BODYSTRUCTURE	= 0x00002000,
	MAIL_FETCH_IMAP_ENVELOPE	= 0x00004000,
	MAIL_FETCH_FROM_ENVELOPE	= 0x00008000,
	MAIL_FETCH_HEADER_MD5		= 0x00010000,
	MAIL_FETCH_STORAGE_ID		= 0x00020000,
	MAIL_FETCH_UIDL_BACKEND		= 0x00040000,
	MAIL_FETCH_MAILBOX_NAME		= 0x00080000,
	MAIL_FETCH_SEARCH_RELEVANCY	= 0x00100000,
	MAIL_FETCH_GUID			= 0x00200000,
	MAIL_FETCH_POP3_ORDER		= 0x00400000,
	MAIL_FETCH_REFCOUNT		= 0x00800000,
	MAIL_FETCH_BODY_SNIPPET		= 0x01000000,
	MAIL_FETCH_REFCOUNT_ID		= 0x02000000,
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
	MAILBOX_TRANSACTION_FLAG_NO_CACHE_DEC	= 0x10,
	/* Sync transaction describes changes to mailbox that already happened
	   to another mailbox with whom we're syncing with (dsync) */
	MAILBOX_TRANSACTION_FLAG_SYNC		= 0x20,
	/* Don't trigger any notifications for this transaction. This
	   especially means the notify plugin. This would normally be used only
	   with _FLAG_SYNC. */
	MAILBOX_TRANSACTION_FLAG_NO_NOTIFY	= 0x40,
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
	/* FIXME: kludge until something better comes along:
	   Request full text search index optimization */
	MAILBOX_SYNC_FLAG_OPTIMIZE		= 0x400
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
	uint32_t messages; /* STATUS_MESSAGES */
	uint32_t recent; /* STATUS_RECENT */
	uint32_t unseen; /* STATUS_UNSEEN */

	uint32_t uidvalidity; /* STATUS_UIDVALIDITY */
	uint32_t uidnext; /* STATUS_UIDNEXT */

	uint32_t first_unseen_seq; /* STATUS_FIRST_UNSEEN_SEQ */
	uint32_t first_recent_uid; /* STATUS_FIRST_RECENT_UID */
	uint32_t last_cached_seq; /* STATUS_LAST_CACHED_SEQ */
	uint64_t highest_modseq; /* STATUS_HIGHESTMODSEQ */
	/* 0 if no private index (STATUS_HIGHESTPVTMODSEQ) */
	uint64_t highest_pvt_modseq;

	/* NULL-terminated array of keywords (STATUS_KEYWORDS) */
	const ARRAY_TYPE(keywords) *keywords;

	/* These flags can be permanently modified (STATUS_PERMANENT_FLAGS) */
	enum mail_flags permanent_flags;
	/* These flags can be modified (STATUS_PERMANENT_FLAGS) */
	enum mail_flags flags;

	/* All keywords can be permanently modified (STATUS_PERMANENT_FLAGS) */
	bool permanent_keywords:1;
	/* More keywords can be created (STATUS_PERMANENT_FLAGS) */
	bool allow_new_keywords:1;
	/* Modseqs aren't permanent (index is in memory) (STATUS_HIGHESTMODSEQ) */
	bool nonpermanent_modseqs:1;
	/* Modseq tracking has never been enabled for this mailbox
	   yet. (STATUS_HIGHESTMODSEQ) */
	bool no_modseq_tracking:1;

	/* Messages have GUIDs (always set) */
	bool have_guids:1;
	/* mailbox_save_set_guid() works (always set) */
	bool have_save_guids:1;
	/* GUIDs are always 128bit (always set) */
	bool have_only_guid128:1;
};

struct mailbox_cache_field {
	const char *name;
	int decision; /* enum mail_cache_decision_type */
	/* last_used is unchanged, if it's (time_t)-1 */
	time_t last_used;
};
ARRAY_DEFINE_TYPE(mailbox_cache_field, struct mailbox_cache_field);

struct mailbox_metadata {
	guid_128_t guid;
	/* sum of virtual size of all messages in mailbox */
	uint64_t virtual_size;
	/* sum of physical size of all messages in mailbox */
	uint64_t physical_size;
	/* timestamp of when the first message was saved.
	   (time_t)-1 if there are no mails in the mailbox. */
	time_t first_save_date;

	/* Fields that have "temp" or "yes" caching decision. */
	const ARRAY_TYPE(mailbox_cache_field) *cache_fields;
	/* Fields that should be precached */
	enum mail_fetch_field precache_fields;

	/* imapc backend returns this based on the remote NAMESPACE reply,
	   while currently other backends return "" and type the same as the
	   mailbox's real namespace type */
	const char *backend_ns_prefix;
	enum mail_namespace_type backend_ns_type;
};

struct mailbox_update {
	/* All non-zero fields are changed. */
	guid_128_t mailbox_guid;
	uint32_t uid_validity;
	uint32_t min_next_uid;
	uint32_t min_first_recent_uid;
	uint64_t min_highest_modseq;
	uint64_t min_highest_pvt_modseq;
	/* Modify caching decisions, terminated by name=NULL */
	const struct mailbox_cache_field *cache_updates;
};

struct mail_transaction_commit_changes {
	/* Unreference the pool to free memory used by these changes. */
	pool_t pool;

	/* UIDVALIDITY for assigned UIDs. */
	uint32_t uid_validity;
	/* UIDs assigned to saved messages. Not necessarily ascending.
	   If UID assignment wasn't required (e.g. LDA), this array may also be
	   empty. Otherwise all of the saved mails got an UID. */
	ARRAY_TYPE(seq_range) saved_uids;

	/* number of modseq changes that couldn't be changed as requested */
	unsigned int ignored_modseq_changes;

	/* Changes that occurred within this transaction */
	enum mail_index_transaction_change changes_mask;
	/* User doesn't have read ACL for the mailbox, so don't show the
	   uid_validity / saved_uids. */
	bool no_read_perm;
};

struct mailbox_sync_rec {
	uint32_t seq1, seq2;
	enum mailbox_sync_type type;
};
struct mailbox_sync_status {
	/* There are expunges that haven't been synced yet */
	bool sync_delayed_expunges:1;
};

struct mailbox_expunge_rec {
	/* IMAP UID */
	uint32_t uid;
	/* 128 bit GUID. If the actual GUID has a different size, this
	   contains last bits of its SHA1 sum. */
	guid_128_t guid_128;
};
ARRAY_DEFINE_TYPE(mailbox_expunge_rec, struct mailbox_expunge_rec);

enum mail_lookup_abort {
	/* Perform everything no matter what it takes */
	MAIL_LOOKUP_ABORT_NEVER = 0,
	/* Abort if the operation would require reading message header/body or
	   otherwise opening the mail file (e.g. with dbox metadata is read by
	   opening and reading the file). This still allows somewhat fast
	   operations to be performed, such as stat()ing a file. */
	MAIL_LOOKUP_ABORT_READ_MAIL,
	/* Abort if the operation can't be done fully using cache file */
	MAIL_LOOKUP_ABORT_NOT_IN_CACHE,
	/* Abort if the operation can't be done fully using cache file.
	 * During this lookup all cache lookups that have "no" decision
	 * will be changed to "tmp". This way the field will start to be
	 * cached in the future. */
	MAIL_LOOKUP_ABORT_NOT_IN_CACHE_START_CACHING,
};

enum mail_access_type {
	MAIL_ACCESS_TYPE_DEFAULT = 0,
	/* Mail is being used for searching */
	MAIL_ACCESS_TYPE_SEARCH,
	/* Mail is being used for sorting results */
	MAIL_ACCESS_TYPE_SORT,
};

struct mail {
	/* always set */
	struct mailbox *box;
	struct mailbox_transaction_context *transaction;
	struct event *event;
	uint32_t seq, uid;

	bool expunged:1;
	bool saving:1; /* This mail is still being saved */
	bool has_nuls:1; /* message data is known to contain NULs */
	bool has_no_nuls:1; /* -''- known to not contain NULs */

	/* Mail's header/body stream was opened within this request.
	   If lookup_abort!=MAIL_LOOKUP_ABORT_NEVER, this can't become TRUE. */
	bool mail_stream_opened:1;
	/* Mail's fast metadata was accessed within this request, e.g. the mail
	   file was stat()ed. If mail_stream_opened==TRUE, this value isn't
	   accurate anymore, because some backends may always set this when
	   stream is opened and some don't. If lookup_abort is
	   MAIL_LOOKUP_ABORT_NOT_IN_CACHE, this can't become TRUE. */
	bool mail_metadata_accessed:1;

	enum mail_access_type access_type;

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
			enum mail_storage_flags flags, const char **error_r)
	ATTR_NULL(2);
int mail_storage_create_full(struct mail_namespace *ns, const char *driver,
			     const char *data, enum mail_storage_flags flags,
			     struct mail_storage **storage_r,
			     const char **error_r) ATTR_NULL(2);
void mail_storage_unref(struct mail_storage **storage);

/* Returns the mail storage settings. */
const struct mail_storage_settings *
mail_storage_get_settings(struct mail_storage *storage) ATTR_PURE;
struct mail_user *mail_storage_get_user(struct mail_storage *storage) ATTR_PURE;

/* Set storage callback functions to use. */
void mail_storage_set_callbacks(struct mail_storage *storage,
				struct mail_storage_callbacks *callbacks,
				void *context) ATTR_NULL(3);

/* Purge storage's mailboxes (freeing disk space from expunged mails),
   if supported by the storage. Otherwise just a no-op. */
int mail_storage_purge(struct mail_storage *storage);

/* Returns the error message of last occurred error. */
const char * ATTR_NOWARN_UNUSED_RESULT
mail_storage_get_last_error(struct mail_storage *storage,
			    enum mail_error *error_r) ATTR_NULL(2);
/* Wrapper for mail_storage_get_last_error(); */
const char * ATTR_NOWARN_UNUSED_RESULT
mailbox_get_last_error(struct mailbox *box, enum mail_error *error_r)
	ATTR_NULL(2);
/* Wrapper for mail_storage_get_last_error(); */
enum mail_error mailbox_get_last_mail_error(struct mailbox *box);

const char * ATTR_NOWARN_UNUSED_RESULT
mail_storage_get_last_internal_error(struct mail_storage *storage,
				     enum mail_error *error_r) ATTR_NULL(2);
/* Wrapper for mail_storage_get_last_internal_error(); */
const char * ATTR_NOWARN_UNUSED_RESULT
mailbox_get_last_internal_error(struct mailbox *box,
				enum mail_error *error_r) ATTR_NULL(2);

/* Save the last error until it's popped. This is useful for cases where the
   storage has already failed, but the cleanup code path changes the error to
   something else unwanted. */
void mail_storage_last_error_push(struct mail_storage *storage);
void mail_storage_last_error_pop(struct mail_storage *storage);

/* Returns TRUE if mailboxes are files. */
bool mail_storage_is_mailbox_file(struct mail_storage *storage) ATTR_PURE;

/* Initialize mailbox without actually opening any files or verifying that
   it exists. Note that append and copy may open the selected mailbox again
   with possibly different readonly-state. */
struct mailbox *mailbox_alloc(struct mailbox_list *list, const char *vname,
			      enum mailbox_flags flags);
/* Like mailbox_alloc(), but use mailbox GUID. */
struct mailbox *mailbox_alloc_guid(struct mailbox_list *list,
				   const guid_128_t guid,
				   enum mailbox_flags flags);
/* Initialize mailbox for a particular user without actually opening any files
   or verifying that it exists. The mname parameter is normally equal to the
   mailbox vname, except when the MAILBOX_FLAG_SPECIAL_USE flag is set, in which
   case it is the special-use flag. */
struct mailbox *
mailbox_alloc_for_user(struct mail_user *user, const char *mname,
		       enum mailbox_flags flags);

/* Set a human-readable reason for why this mailbox is being accessed.
   This is used for logging purposes. */
void mailbox_set_reason(struct mailbox *box, const char *reason);
/* Get mailbox existence state. If auto_boxes=FALSE, return
   MAILBOX_EXISTENCE_NONE for autocreated mailboxes that haven't been
   physically created yet */
int mailbox_exists(struct mailbox *box, bool auto_boxes,
		   enum mailbox_existence *existence_r);
/* Open the mailbox. If this function isn't called explicitly, it's also called
   internally by lib-storage when necessary. */
int mailbox_open(struct mailbox *box);
/* Open mailbox as read-only using the given stream as input. */
int mailbox_open_stream(struct mailbox *box, struct istream *input);
/* Close mailbox. Same as if mailbox was freed and re-allocated. */
void mailbox_close(struct mailbox *box);
/* Close and free the mailbox. */
void mailbox_free(struct mailbox **box);

/* Returns TRUE if box1 points to the same mailbox as ns2/vname2. */
bool mailbox_equals(const struct mailbox *box1,
		    const struct mail_namespace *ns2,
		    const char *vname2) ATTR_PURE;
/* Returns TRUE if the mailbox is user's INBOX or another user's shared INBOX */
bool mailbox_is_any_inbox(struct mailbox *box);

/* Returns TRUE if the mailbox has the specified special use flag assigned. */
bool mailbox_has_special_use(struct mailbox *box, const char *special_use);

/* Change mailbox_verify_create_name() to not verify new mailbox name
   restrictions (but still check that it's a valid existing name). This is
   mainly used by dsync to make sure the sync works even though the original
   name isn't valid anymore. */
void mailbox_skip_create_name_restrictions(struct mailbox *box, bool set);
/* Returns -1 if mailbox_create() is guaranteed to fail because the mailbox
   name is invalid, 0 not. The error message contains a reason. */
int mailbox_verify_create_name(struct mailbox *box);
/* Create a mailbox. Returns failure if it already exists. Mailbox name is
   allowed to contain multiple new nonexistent hierarchy levels. If directory
   is TRUE, the mailbox should be created so that it can contain children. The
   mailbox itself doesn't have to be created as long as it shows up in LIST.
   If update is non-NULL, its contents are used to set initial mailbox
   metadata. */
int mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		   bool directory) ATTR_NULL(2);
/* Update existing mailbox's metadata. */
int mailbox_update(struct mailbox *box, const struct mailbox_update *update);
/* Delete mailbox (and its parent directory, if it has no siblings) */
int mailbox_delete(struct mailbox *box);
/* Delete mailbox, but only if it's empty. If it's not, fails with
   MAIL_ERROR_EXISTS. */
int mailbox_delete_empty(struct mailbox *box);
/* Rename mailbox (and its children). Renaming across different mailbox lists
   is possible only between private namespaces and storages of the same type.
   If the rename fails, the error is set to src's storage. */
int mailbox_rename(struct mailbox *src, struct mailbox *dest);
/* Subscribe/unsubscribe mailbox. Subscribing to
   nonexistent mailboxes is optional. */
int mailbox_set_subscribed(struct mailbox *box, bool set);
/* Returns TRUE if mailbox is subscribed, FALSE if not. This function
   doesn't refresh the subscriptions list, but assumes that it's been done by
   e.g. mailbox_list_iter*(). */
bool mailbox_is_subscribed(struct mailbox *box);

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
/* Returns the mailbox's settings, or NULL if there are none. */
const struct mailbox_settings *
mailbox_settings_find(struct mail_namespace *ns, const char *vname);

/* Returns the (virtual) name of the given mailbox. */
const char *mailbox_get_vname(const struct mailbox *box) ATTR_PURE;
/* Returns the backend name of given mailbox. */
const char *mailbox_get_name(const struct mailbox *box) ATTR_PURE;

/* Returns TRUE if mailbox is read-only. */
bool mailbox_is_readonly(struct mailbox *box);
/* Returns TRUE if two mailboxes point to the same physical mailbox. */
bool mailbox_backends_equal(const struct mailbox *box1,
			    const struct mailbox *box2);
/* Returns TRUE if mailbox is now in inconsistent state, meaning that
   the message IDs etc. may have changed - only way to recover this
   would be to fully close the mailbox and reopen it. With IMAP
   connection this would mean a forced disconnection since we can't
   do forced CLOSE. */
bool mailbox_is_inconsistent(struct mailbox *box);

/* Gets the mailbox status information. If mailbox isn't opened yet, try to
   return the results from mailbox list indexes. Otherwise the mailbox is
   opened and synced. If the mailbox is already opened, no syncing is done
   automatically. */
int mailbox_get_status(struct mailbox *box, enum mailbox_status_items items,
		       struct mailbox_status *status_r);
/* Gets the mailbox status, requires that mailbox is already opened. */
void mailbox_get_open_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status_r);
/* Gets mailbox metadata */
int mailbox_get_metadata(struct mailbox *box, enum mailbox_metadata_items items,
			 struct mailbox_metadata *metadata_r);
/* Returns a mask of flags that are private to user in this mailbox
   (as opposed to flags shared between users). */
enum mail_flags mailbox_get_private_flags_mask(struct mailbox *box);

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
void mailbox_notify_changes(struct mailbox *box,
			    mailbox_notify_callback_t *callback, void *context)
	ATTR_NULL(3);
#define mailbox_notify_changes(box, callback, context) \
	  mailbox_notify_changes(box, (mailbox_notify_callback_t *)callback, \
		(void *)((char *)context - CALLBACK_TYPECHECK(callback, \
			void (*)(struct mailbox *, typeof(context)))))
void mailbox_notify_changes_stop(struct mailbox *box);

struct mailbox_transaction_context *
mailbox_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags,
			  const char *reason);
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

/* Initialize header lookup for given headers. */
struct mailbox_header_lookup_ctx *
mailbox_header_lookup_init(struct mailbox *box, const char *const headers[]);
void mailbox_header_lookup_ref(struct mailbox_header_lookup_ctx *ctx);
void mailbox_header_lookup_unref(struct mailbox_header_lookup_ctx **ctx);
/* Merge two header lookups. */
struct mailbox_header_lookup_ctx *
mailbox_header_lookup_merge(const struct mailbox_header_lookup_ctx *hdr1,
			    const struct mailbox_header_lookup_ctx *hdr2);

/* Initialize new search request. If sort_program is non-NULL, the messages are
   returned in the requested order, otherwise from first to last. */
struct mail_search_context * ATTR_NULL(3, 5)
mailbox_search_init(struct mailbox_transaction_context *t,
		    struct mail_search_args *args,
		    const enum mail_sort_type *sort_program,
		    enum mail_fetch_field wanted_fields,
		    struct mailbox_header_lookup_ctx *wanted_headers);
/* Deinitialize search request. */
int mailbox_search_deinit(struct mail_search_context **ctx);
/* Search the next message. Returns TRUE if found, FALSE if not. */
bool mailbox_search_next(struct mail_search_context *ctx, struct mail **mail_r);
/* Like mailbox_search_next(), but don't spend too much time searching.
   Returns FALSE with tryagain_r=FALSE if finished, and tryagain_r=TRUE if
   more results will be returned by calling the function again. */
bool mailbox_search_next_nonblock(struct mail_search_context *ctx,
				  struct mail **mail_r, bool *tryagain_r);
/* Returns TRUE if some messages were already expunged and we couldn't
   determine correctly if those messages should have been returned in this
   search. */
bool mailbox_search_seen_lost_data(struct mail_search_context *ctx);
/* Detach the given mail from the search context. This allows the mail to live
   even after mail_search_context has been freed. */
void mailbox_search_mail_detach(struct mail_search_context *ctx,
				struct mail *mail);

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

/* Build mail_keywords from NULL-terminated keywords list. Any duplicate
   keywords are removed. Returns 0 if successful, -1 if there are invalid
   keywords (error is set). */
int mailbox_keywords_create(struct mailbox *box, const char *const keywords[],
			    struct mail_keywords **keywords_r);
/* Like mailbox_keywords_create(), except ignore invalid keywords. */
struct mail_keywords *
mailbox_keywords_create_valid(struct mailbox *box,
			      const char *const keywords[]);
struct mail_keywords *
mailbox_keywords_create_from_indexes(struct mailbox *box,
				     const ARRAY_TYPE(keyword_indexes) *idx);
/* Return union of two mail_keywords. They must be created in the same
   mailbox. */
struct mail_keywords *mailbox_keywords_merge(struct mail_keywords *keywords1,
					     struct mail_keywords *keywords2);
void mailbox_keywords_ref(struct mail_keywords *keywords);
void mailbox_keywords_unref(struct mail_keywords **keywords);
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
/* Specify ordering for POP3 messages. The default is to add them to the end
   of the mailbox. Not all backends support this. */
void mailbox_save_set_pop3_order(struct mail_save_context *ctx,
				 unsigned int order);
/* Returns the destination mail */
struct mail *mailbox_save_get_dest_mail(struct mail_save_context *ctx);
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
/* Move the given message. This is usually equivalent to copy+expunge,
   but without enforcing quota. */
int mailbox_move(struct mail_save_context **ctx, struct mail *mail);
/* Same as mailbox_copy(), but treat the message as if it's being saved,
   not copied. (For example: New mail delivered to multiple maildirs, with
   each mails being hard link copies.) */
int mailbox_save_using_mail(struct mail_save_context **ctx, struct mail *mail);

struct mail *mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
	ATTR_NULL(3);
void mail_free(struct mail **mail);
void mail_set_seq(struct mail *mail, uint32_t seq);
/* Returns TRUE if successful, FALSE if message doesn't exist.
   mail_*() functions shouldn't be called if FALSE is returned. */
bool mail_set_uid(struct mail *mail, uint32_t uid);

/* Add wanted fields/headers on top of existing ones. These will be forgotten
   after the next mail_set_seq/uid() that closes the existing mail. Note that
   it's valid to call this function while there is no mail assigned
   (mail->seq==0), i.e. this is called before any mail_set_seq/uid() or after
   mail.close(). */
void mail_add_temp_wanted_fields(struct mail *mail,
				 enum mail_fetch_field fields,
				 struct mailbox_header_lookup_ctx *headers)
	ATTR_NULL(3);

/* Returns message's flags */
enum mail_flags mail_get_flags(struct mail *mail);
/* Returns message's keywords */
const char *const *mail_get_keywords(struct mail *mail);
/* Returns message's keywords */
const ARRAY_TYPE(keyword_indexes) *mail_get_keyword_indexes(struct mail *mail);
/* Returns message's modseq */
uint64_t mail_get_modseq(struct mail *mail);
/* Returns message's private modseq, or 0 if message hasn't had any
   private flag changes. This is useful only for shared mailboxes that have
   a private index defined. */
uint64_t mail_get_pvt_modseq(struct mail *mail);

/* Returns message's MIME parts */
int mail_get_parts(struct mail *mail, struct message_part **parts_r);

/* Get the Date-header of the mail. Timezone is in minutes. date=0 if it
   wasn't found or it was invalid. */
int mail_get_date(struct mail *mail, time_t *date_r, int *timezone_r);
/* Get the time when the mail was received (IMAP INTERNALDATE). */
int mail_get_received_date(struct mail *mail, time_t *date_r);
/* Get the time when the mail was saved into this mailbox. This returns -1 on
   error, 0 if a real save date is not supported and a fall-back date is used,
   and 1 when a save date was successfully retrieved. */
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
   Returns 1 if headers were found, 0 if not (value_r[0]==NULL) or
   -1 if error. */
int mail_get_headers(struct mail *mail, const char *field,
		     const char *const **value_r);
/* Like mail_get_headers(), but decode MIME encoded words to UTF-8.
   Also multiline headers are returned unfolded.
   Do not use for structured fields (see mail_get_first_header_utf8()). */
int mail_get_headers_utf8(struct mail *mail, const char *field,
			  const char *const **value_r);
/* Returns stream containing specified headers. The returned stream will be
   automatically freed when the mail is closed, or when another
   mail_get_header_stream() call is made (so you can't have multiple header
   streams open at the same time). */
int mail_get_header_stream(struct mail *mail,
			   struct mailbox_header_lookup_ctx *headers,
			   struct istream **stream_r);
/* Returns input stream pointing to beginning of message header.
   hdr_size and body_size are updated unless they're NULL. The returned stream
   is destroyed automatically, don't unreference it. */
int mail_get_stream(struct mail *mail, struct message_size *hdr_size,
		    struct message_size *body_size, struct istream **stream_r)
	ATTR_NULL(2, 3);
/* Same as mail_get_stream(), but specify a reason why the mail is being read.
   This can be useful for debugging purposes. */
int mail_get_stream_because(struct mail *mail, struct message_size *hdr_size,
			    struct message_size *body_size,
			    const char *reason, struct istream **stream_r)
	ATTR_NULL(2, 3);
/* Similar to mail_get_stream(), but the stream may or may not contain the
   message body. */
int mail_get_hdr_stream(struct mail *mail, struct message_size *hdr_size,
			struct istream **stream_r) ATTR_NULL(2);
/* Same as mail_get_hdr_stream(), but specify a reason why the header is being
   read. This can be useful for debugging purposes. */
int mail_get_hdr_stream_because(struct mail *mail,
				struct message_size *hdr_size,
				const char *reason, struct istream **stream_r);
/* Returns the message part's body decoded to 8bit binary. If the
   Content-Transfer-Encoding isn't supported, returns -1 and sets error to
   MAIL_ERROR_CONVERSION. If the part refers to a multipart, all of its
   children are returned decoded. */
int mail_get_binary_stream(struct mail *mail, const struct message_part *part,
			   bool include_hdr, uoff_t *size_r,
			   bool *binary_r, struct istream **stream_r);
/* Like mail_get_binary_stream(), but only return the size. */
int mail_get_binary_size(struct mail *mail, const struct message_part *part,
			 bool include_hdr, uoff_t *size_r,
			 unsigned int *lines_r);

/* Get any of the "special" fields. Unhandled specials are returned as "". */
int mail_get_special(struct mail *mail, enum mail_fetch_field field,
		     const char **value_r);
/* Returns the mail for the physical message. Normally this is the mail itself,
   but in virtual mailboxes it points to the backend mailbox. */
int mail_get_backend_mail(struct mail *mail, struct mail **real_mail_r);

/* Retrieve and parse the value of the Message-ID header field. Returns 1 if the
   header was found and it contains a valid message ID, 0 if the header was not
   found or no valid message ID was contained in it, and -1 if an error occurred
   while retrieving the header. Returns the message ID value including '<' and
   '>' in the *value_r return parameter or NULL if the header wasn't found or
   its value was invalid. */
int mail_get_message_id(struct mail *mail, const char **value_r);

/* Update message flags. */
void mail_update_flags(struct mail *mail, enum modify_type modify_type,
		       enum mail_flags flags);
/* Update message keywords. */
void mail_update_keywords(struct mail *mail, enum modify_type modify_type,
			  struct mail_keywords *keywords);
/* Update message's modseq to be at least min_modseq. */
void mail_update_modseq(struct mail *mail, uint64_t min_modseq);
/* Update message's private modseq to be at least min_pvt_modseq. */
void mail_update_pvt_modseq(struct mail *mail, uint64_t min_pvt_modseq);

/* Update message's POP3 UIDL (if possible). */
void mail_update_pop3_uidl(struct mail *mail, const char *uidl);
/* Expunge this message. Sequence numbers don't change until commit. */
void mail_expunge(struct mail *mail);

/* Add missing fields to cache. */
void mail_precache(struct mail *mail);
/* Mark a cached field corrupted and have it recalculated. */
void mail_set_cache_corrupted(struct mail *mail,
			      enum mail_fetch_field field,
			      const char *reason);

/* Return 128 bit GUID using input string. If guid is already 128 bit hex
   encoded, it's returned as-is. Otherwise SHA1 sum is taken and its last
   128 bits are returned. */
void mail_generate_guid_128_hash(const char *guid, guid_128_t guid_128_r);

/* Parse a human-writable string into a timestamp. utc_r controls whether
   the returned timestamp should be treated as an exact UTC time (TRUE), or
   whether this is a human-given date where the timestamp could be adjusted
   by the matched mails' timezones (see MAIL_SEARCH_ARG_FLAG_USE_TZ).

   Returns 0 and timestamp on success, -1 if the string couldn't be parsed.
   Currently supported string formats: yyyy-mm-dd (utc=FALSE),
   imap date (utc=FALSE), unix timestamp (utc=TRUE), interval (e.g. n days,
   utc=TRUE). */
int mail_parse_human_timestamp(const char *str, time_t *timestamp_r,
			       bool *utc_r);

#endif
