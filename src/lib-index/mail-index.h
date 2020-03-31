#ifndef MAIL_INDEX_H
#define MAIL_INDEX_H

#include "file-lock.h"
#include "fsync-mode.h"
#include "guid.h"
#include "mail-types.h"
#include "seq-range-array.h"

#define MAIL_INDEX_MAJOR_VERSION 7
#define MAIL_INDEX_MINOR_VERSION 3

#define MAIL_INDEX_HEADER_MIN_SIZE 120

/* Log a warning when transaction log has been locked for this many seconds.
   This lock is held also between mail_index_sync_begin()..commit(). */
#define MAIL_TRANSACTION_LOG_LOCK_WARN_SECS 30

enum mail_index_open_flags {
	/* Create index if it doesn't exist */
	MAIL_INDEX_OPEN_FLAG_CREATE		= 0x01,
	/* Don't try to mmap() index files */
	MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE	= 0x04,
	/* Rely on O_EXCL when creating dotlocks */
	MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL	= 0x10,
	/* Flush NFS attr/data/write cache when necessary */
	MAIL_INDEX_OPEN_FLAG_NFS_FLUSH		= 0x40,
	/* Open the index read-only */
	MAIL_INDEX_OPEN_FLAG_READONLY		= 0x80,
	/* Create backups of dovecot.index files once in a while */
	MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS	= 0x100,
	/* If we run out of disk space, fail modifications instead of moving
	   indexes to memory. */
	MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY	= 0x200,
	/* We're only going to save new messages to the index.
	   Avoid unnecessary reads. */
	MAIL_INDEX_OPEN_FLAG_SAVEONLY		= 0x400,
	/* Enable debug logging */
	MAIL_INDEX_OPEN_FLAG_DEBUG		= 0x800,
	/* MAIL_INDEX_MAIL_FLAG_DIRTY can be used as a backend-specific flag.
	   All special handling of the flag is disabled by this. */
	MAIL_INDEX_OPEN_FLAG_NO_DIRTY		= 0x1000,
};

enum mail_index_header_compat_flags {
	MAIL_INDEX_COMPAT_LITTLE_ENDIAN		= 0x01
};

enum mail_index_header_flag {
	/* Index file is corrupted, reopen or recreate it. */
	MAIL_INDEX_HDR_FLAG_CORRUPTED		= 0x0001,
	MAIL_INDEX_HDR_FLAG_HAVE_DIRTY		= 0x0002,
	/* Index has been fsck'd. The caller may want to resync the index
	   to make sure it's valid and drop this flag. */
	MAIL_INDEX_HDR_FLAG_FSCKD		= 0x0004,
};

enum mail_index_mail_flags {
	/* For private use by backend. Replacing flags doesn't change this. */
	MAIL_INDEX_MAIL_FLAG_BACKEND		= 0x40,
	/* Message flags haven't been written to backend. If
	   MAIL_INDEX_OPEN_FLAG_NO_DIRTY is set, this is treated as a
	   backend-specific flag with no special internal handling. */
	MAIL_INDEX_MAIL_FLAG_DIRTY		= 0x80,
	/* Force updating this message's modseq via a flag update record */
	MAIL_INDEX_MAIL_FLAG_UPDATE_MODSEQ	= 0x100
};

#define MAIL_INDEX_FLAGS_MASK \
	(MAIL_ANSWERED | MAIL_FLAGGED | MAIL_DELETED | MAIL_SEEN | MAIL_DRAFT)

struct mail_index_header {
	/* major version is increased only when you can't have backwards
	   compatibility. minor version is increased when header size is
	   increased to contain new non-critical fields. */
	uint8_t major_version;
	uint8_t minor_version;

	uint16_t base_header_size;
	uint32_t header_size; /* base + extended header size */
	uint32_t record_size;

	uint8_t compat_flags; /* enum mail_index_header_compat_flags */
	uint8_t unused[3];

	uint32_t indexid;
	uint32_t flags;

	uint32_t uid_validity;
	uint32_t next_uid;

	uint32_t messages_count;
	uint32_t unused_old_recent_messages_count;
	uint32_t seen_messages_count;
	uint32_t deleted_messages_count;

	uint32_t first_recent_uid;
	/* these UIDs may not exist and may not even be unseen/deleted */
	uint32_t first_unseen_uid_lowwater;
	uint32_t first_deleted_uid_lowwater;

	uint32_t log_file_seq;
	/* non-external records between tail..head haven't been committed to
	   mailbox yet. */
	uint32_t log_file_tail_offset;
	uint32_t log_file_head_offset;

	uint32_t unused_old_sync_size_part1;
	/* Timestamp of when .log was rotated into .log.2. This can be used to
	   optimize checking when it's time to unlink it without stat()ing it.
	   0 = unknown, -1 = .log.2 doesn't exists. */
	uint32_t log2_rotate_time;
	uint32_t last_temp_file_scan;

	/* daily first UIDs that have been added to index. */
	uint32_t day_stamp;
	uint32_t day_first_uid[8];
};

#define MAIL_INDEX_RECORD_MIN_SIZE (sizeof(uint32_t) + sizeof(uint8_t))
struct mail_index_record {
	uint32_t uid;
	uint8_t flags; /* enum mail_flags | enum mail_index_mail_flags */
};

struct mail_keywords {
	struct mail_index *index;
	unsigned int count;
	int refcount;

        /* variable sized list of keyword indexes */
	unsigned int idx[FLEXIBLE_ARRAY_MEMBER];
};

enum mail_index_transaction_flags {
	/* If transaction is marked as hidden, the changes are marked with
	   hidden=TRUE when the view is synchronized. */
	MAIL_INDEX_TRANSACTION_FLAG_HIDE		= 0x01,
	/* External transactions describe changes to mailbox that have already
	   happened. */
	MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL		= 0x02,
	/* Don't add flag updates unless they actually change something.
	   This is reliable only when syncing, otherwise someone else might
	   have already committed a transaction that had changed the flags. */
	MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES	= 0x04,
	/* fsync() this transaction (unless fsyncs are disabled) */
	MAIL_INDEX_TRANSACTION_FLAG_FSYNC		= 0x08,
	/* Sync transaction describes changes to mailbox that already happened
	   to another mailbox with whom we're syncing with (dsync) */
	MAIL_INDEX_TRANSACTION_FLAG_SYNC		= 0x10
};

enum mail_index_sync_type {
	MAIL_INDEX_SYNC_TYPE_EXPUNGE		= 0x02,
	MAIL_INDEX_SYNC_TYPE_FLAGS		= 0x04,
	MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD	= 0x08,
	MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE	= 0x10
};

enum mail_index_fsync_mask {
	MAIL_INDEX_FSYNC_MASK_APPENDS	= 0x01,
	MAIL_INDEX_FSYNC_MASK_EXPUNGES	= 0x02,
	MAIL_INDEX_FSYNC_MASK_FLAGS	= 0x04,
	MAIL_INDEX_FSYNC_MASK_KEYWORDS	= 0x08
};

enum mail_index_sync_flags {
	/* Resync all dirty messages' flags. */
	MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY	= 0x01,
	/* Drop recent flags from all messages */
	MAIL_INDEX_SYNC_FLAG_DROP_RECENT	= 0x02,
	/* Create the transaction with AVOID_FLAG_UPDATES flag */
	MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES	= 0x04,
	/* If there are no new transactions and nothing else to do,
	   return 0 in mail_index_sync_begin() */
	MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES	= 0x08,
	/* Create the transaction with FSYNC flag */
	MAIL_INDEX_SYNC_FLAG_FSYNC		= 0x10,
	/* If we see "delete index" request transaction, finish it.
	   This flag also allows committing more changes to a deleted index. */
	MAIL_INDEX_SYNC_FLAG_DELETING_INDEX	= 0x20,
	/* Same as MAIL_INDEX_SYNC_FLAG_DELETING_INDEX, but finish index
	   deletion only once and fail the rest (= avoid race conditions when
	   multiple processes try to mark the index deleted) */
	MAIL_INDEX_SYNC_FLAG_TRY_DELETING_INDEX	= 0x40,
	/* Update header's tail_offset to head_offset, even if it's the only
	   thing we do and there's no strict need for it. */
	MAIL_INDEX_SYNC_FLAG_UPDATE_TAIL_OFFSET	= 0x80
};

enum mail_index_view_sync_flags {
	/* Don't sync expunges */
	MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES		= 0x01,
	/* Make sure view isn't inconsistent after syncing. This also means
	   that you don't care about view_sync_next()'s output, so it won't
	   return anything. */
	MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT	= 0x02
};

struct mail_index_sync_rec {
	uint32_t uid1, uid2;
	enum mail_index_sync_type type;

	/* MAIL_INDEX_SYNC_TYPE_FLAGS: */
	uint8_t add_flags;
	uint8_t remove_flags;

	/* MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD, .._REMOVE: */
	unsigned int keyword_idx;

	/* MAIL_INDEX_SYNC_TYPE_EXPUNGE: */
	guid_128_t guid_128;
};

enum mail_index_view_sync_type {
	/* Flags or keywords changed */
	MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS		= 0x01,
	MAIL_INDEX_VIEW_SYNC_TYPE_MODSEQ	= 0x02
};

struct mail_index_view_sync_rec {
	uint32_t uid1, uid2;
	enum mail_index_view_sync_type type;

	/* TRUE if this was a hidden transaction. */
	bool hidden:1;
};

enum mail_index_transaction_change {
	MAIL_INDEX_TRANSACTION_CHANGE_APPEND	= BIT(0),
	MAIL_INDEX_TRANSACTION_CHANGE_EXPUNGE	= BIT(1),
	MAIL_INDEX_TRANSACTION_CHANGE_FLAGS	= BIT(2),
	MAIL_INDEX_TRANSACTION_CHANGE_KEYWORDS	= BIT(3),
	MAIL_INDEX_TRANSACTION_CHANGE_MODSEQ	= BIT(4),
	MAIL_INDEX_TRANSACTION_CHANGE_ATTRIBUTE	= BIT(5),

	MAIL_INDEX_TRANSACTION_CHANGE_OTHERS	= BIT(30),
};

struct mail_index_transaction_commit_result {
	/* seq/offset points to end of transaction */
	uint32_t log_file_seq;
	uoff_t log_file_offset;
	/* number of bytes in the written transaction.
	   all of it was written to the same file. */
	uoff_t commit_size;

	enum mail_index_transaction_change changes_mask;
	unsigned int ignored_modseq_changes;
};

struct mail_index_base_optimization_settings {
	/* Rewrite the index when the number of bytes that needs to be read
	   from the .log on refresh is between these min/max values. */
	uoff_t rewrite_min_log_bytes;
	uoff_t rewrite_max_log_bytes;
};

struct mail_index_log_optimization_settings {
	/* Rotate transaction log after it's a) min_size or larger and it was
	   created at least min_age_secs or b) larger than max_size. */
	uoff_t min_size;
	uoff_t max_size;
	unsigned int min_age_secs;

	/* Delete .log.2 when it's older than log2_stale_secs. Don't be too
	   eager, because older files are useful for QRESYNC and dsync. */
	unsigned int log2_max_age_secs;
};

struct mail_index_cache_optimization_settings {
	/* Drop fields that haven't been accessed for n seconds */
	unsigned int unaccessed_field_drop_secs;
	/* If cache record becomes larger than this, don't add it. */
	unsigned int record_max_size;

	/* Maximum size for the cache file. Internally the limit is 1 GB. */
	uoff_t max_size;
	/* Never purge the file if it's smaller than this */
	uoff_t purge_min_size;
	/* Purge the file when n% of records are deleted */
	unsigned int purge_delete_percentage;
	/* Purge the file when n% of rows contain continued rows.
	   For example 200% means that the record has 2 continued rows, i.e.
	   it exists in 3 separate segments in the cache file. */
	unsigned int purge_continued_percentage;
	/* Purge the file when we need to follow more than n next_offsets to
	   find the latest cache header. */
	unsigned int purge_header_continue_count;
};

struct mail_index_optimization_settings {
	struct mail_index_base_optimization_settings index;
	struct mail_index_log_optimization_settings log;
	struct mail_index_cache_optimization_settings cache;
};

struct mail_index;
struct mail_index_map;
struct mail_index_view;
struct mail_index_transaction;
struct mail_index_sync_ctx;
struct mail_index_view_sync_ctx;

struct mail_index *mail_index_alloc(struct event *parent_event,
				    const char *dir, const char *prefix);
void mail_index_free(struct mail_index **index);

/* Change .cache file's directory. */
void mail_index_set_cache_dir(struct mail_index *index, const char *dir);
/* Specify how often to do fsyncs. If mode is FSYNC_MODE_OPTIMIZED, the mask
   can be used to specify which transaction types to fsync. */
void mail_index_set_fsync_mode(struct mail_index *index, enum fsync_mode mode,
			       enum mail_index_fsync_mask mask);
/* Try to set the index's permissions based on its index directory. Returns
   TRUE if successful (directory existed), FALSE if mail_index_set_permissions()
   should be called. */
bool mail_index_use_existing_permissions(struct mail_index *index);
void mail_index_set_permissions(struct mail_index *index,
				mode_t mode, gid_t gid, const char *gid_origin);
/* Set locking method and maximum time to wait for a lock
   (UINT_MAX = default). */
void mail_index_set_lock_method(struct mail_index *index,
				enum file_lock_method lock_method,
				unsigned int max_timeout_secs);
/* Override the default optimization-related settings. Anything set to 0 will
   use the default. */
void mail_index_set_optimization_settings(struct mail_index *index,
	const struct mail_index_optimization_settings *set);
/* When creating a new index file or reseting an existing one, add the given
   extension header data immediately to it. */
void mail_index_set_ext_init_data(struct mail_index *index, uint32_t ext_id,
				  const void *data, size_t size);

/* Open index. Returns 1 if ok, 0 if index doesn't exist and CREATE flags
   wasn't given, -1 if error. */
int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags);
/* Open or create index. Returns 0 if ok, -1 if error. */
int mail_index_open_or_create(struct mail_index *index,
			      enum mail_index_open_flags flags);
void mail_index_close(struct mail_index *index);
/* unlink() all the index files. */
int mail_index_unlink(struct mail_index *index);

/* Returns TRUE if index is currently in memory. */
bool mail_index_is_in_memory(struct mail_index *index);
/* Move the index into memory. Returns 0 if ok, -1 if error occurred. */
int mail_index_move_to_memory(struct mail_index *index);

struct mail_cache *mail_index_get_cache(struct mail_index *index);

/* Refresh index so mail_index_lookup*() will return latest values. Note that
   immediately after this call there may already be changes, so if you need to
   rely on validity of the returned values, use some external locking for it. */
int ATTR_NOWARN_UNUSED_RESULT
mail_index_refresh(struct mail_index *index);

/* View can be used to look into index. Sequence numbers inside view change
   only when you synchronize it. The view acquires required locks
   automatically, but you'll have to drop them manually. */
struct mail_index_view *
mail_index_view_open(struct mail_index *index,
		     const char *source_filename, unsigned int source_linenum);
#define mail_index_view_open(index) \
	mail_index_view_open(index, __FILE__, __LINE__)
void mail_index_view_close(struct mail_index_view **view);

/* Returns the index for given view. */
struct mail_index *mail_index_view_get_index(struct mail_index_view *view);
/* Returns number of mails in view. */
uint32_t mail_index_view_get_messages_count(struct mail_index_view *view);
/* Returns TRUE if we lost track of changes for some reason. */
bool mail_index_view_is_inconsistent(struct mail_index_view *view);
/* Returns number of transactions open for the view. */
unsigned int
mail_index_view_get_transaction_count(struct mail_index_view *view);

/* Transaction has to be opened to be able to modify index. You can have
   multiple transactions open simultaneously. Committed transactions won't
   show up until you've synchronized the view. Expunges won't show up until
   you've synchronized the mailbox (mail_index_sync_begin). */
struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     enum mail_index_transaction_flags flags);
int mail_index_transaction_commit(struct mail_index_transaction **t);
int mail_index_transaction_commit_full(struct mail_index_transaction **t,
				       struct mail_index_transaction_commit_result *result_r);
void mail_index_transaction_rollback(struct mail_index_transaction **t);
/* Discard all changes in the transaction. */
void mail_index_transaction_reset(struct mail_index_transaction *t);
/* When committing transaction, drop flag/keyword updates for messages whose
   mdoseq is larger than max_modseq. Save those messages' sequences to the
   given array. */
void mail_index_transaction_set_max_modseq(struct mail_index_transaction *t,
					   uint64_t max_modseq,
					   ARRAY_TYPE(seq_range) *seqs);
/* Returns the resulting highest-modseq after this commit. This can be called
   only if transaction log is locked, which normally means only during mail
   index syncing. If there are any appends, they all must have been assigned
   UIDs before calling this. */
uint64_t mail_index_transaction_get_highest_modseq(struct mail_index_transaction *t);

/* Returns the view transaction was created for. */
struct mail_index_view *
mail_index_transaction_get_view(struct mail_index_transaction *t);
/* Returns TRUE if the given sequence is being expunged in this transaction. */
bool mail_index_transaction_is_expunged(struct mail_index_transaction *t,
					uint32_t seq);

/* Returns a view containing the mailbox state after changes in transaction
   are applied. The view can still be used after transaction has been
   committed. */
struct mail_index_view *
mail_index_transaction_open_updated_view(struct mail_index_transaction *t);

/* Begin synchronizing mailbox with index file. Returns 1 if ok,
   0 if MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES is set and there's nothing to
   sync, -1 if error.

   mail_index_sync_next() returns all changes from previously committed
   transactions which haven't yet been committed to the actual mailbox.
   They're returned in ascending order and they never overlap (if we add more
   sync types, then they might). You must go through all of them and update
   the mailbox accordingly.

   Changes done to the returned transaction are expected to describe the
   mailbox's current state.

   The returned view already contains all the changes (except expunge
   requests). After applying sync records on top of backend flags they should
   match flags in the view. If they don't, there have been external changes.

   Returned expunges are treated as expunge requests. They're not really
   removed from the index until you mark them expunged to the returned
   transaction. If it's not possible to expunge the message (e.g. permission
   denied), simply don't mark them expunged.

   Returned sequence numbers describe the mailbox state at the beginning of
   synchronization, ie. expunges don't affect them. */
int mail_index_sync_begin(struct mail_index *index,
			  struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  struct mail_index_transaction **trans_r,
			  enum mail_index_sync_flags flags);
/* Like mail_index_sync_begin(), but returns 1 if OK and if index is already
   synchronized up to the given log_file_seq+offset, the synchronization isn't
   started and this function returns 0. This should be done when you wish to
   sync your committed transaction instead of doing a full mailbox
   synchronization. */
int mail_index_sync_begin_to(struct mail_index *index,
			     struct mail_index_sync_ctx **ctx_r,
			     struct mail_index_view **view_r,
			     struct mail_index_transaction **trans_r,
			     uint32_t log_file_seq, uoff_t log_file_offset,
			     enum mail_index_sync_flags flags);
/* Returns TRUE if it currently looks like syncing would return changes. */
bool mail_index_sync_have_any(struct mail_index *index,
			      enum mail_index_sync_flags flags);
/* Returns TRUE if it currently looks like syncing would return expunges. */
bool mail_index_sync_have_any_expunges(struct mail_index *index);
/* Returns the log file seq+offsets for the area which this sync is handling. */
void mail_index_sync_get_offsets(struct mail_index_sync_ctx *ctx,
				 uint32_t *seq1_r, uoff_t *offset1_r,
				 uint32_t *seq2_r, uoff_t *offset2_r);
/* Returns -1 if error, 0 if sync is finished, 1 if record was filled. */
bool mail_index_sync_next(struct mail_index_sync_ctx *ctx,
			  struct mail_index_sync_rec *sync_rec);
/* Returns TRUE if there's more to sync. */
bool mail_index_sync_have_more(struct mail_index_sync_ctx *ctx);
/* Returns TRUE if sync has any expunges to handle. */
bool mail_index_sync_has_expunges(struct mail_index_sync_ctx *ctx);
/* Reset syncing to initial state after mail_index_sync_begin(), so you can
   go through all the sync records again with mail_index_sync_next(). */
void mail_index_sync_reset(struct mail_index_sync_ctx *ctx);
/* Update result when refreshing index at the end of sync. */
void mail_index_sync_set_commit_result(struct mail_index_sync_ctx *ctx,
				       struct mail_index_transaction_commit_result *result);
/* Don't log a warning even if syncing took over
   MAIL_TRANSACTION_LOG_LOCK_WARN_SECS seconds. Usually this is called because
   the caller itself already logged a warning about it. */
void mail_index_sync_no_warning(struct mail_index_sync_ctx *ctx);
/* If a warning is logged because syncing took over
   MAIL_TRANSACTION_LOG_LOCK_WARN_SECS seconds, log this as the reason for the
   syncing. */
void mail_index_sync_set_reason(struct mail_index_sync_ctx *ctx,
				const char *reason);
/* Commit synchronization by writing all changes to mail index file. */
int mail_index_sync_commit(struct mail_index_sync_ctx **ctx);
/* Rollback synchronization - none of the changes listed by sync_next() are
   actually written to index file. */
void mail_index_sync_rollback(struct mail_index_sync_ctx **ctx);

/* Mark index file corrupted. Invalidates all views. */
void mail_index_mark_corrupted(struct mail_index *index);
/* Check and fix any found problems. Returns -1 if we couldn't lock for sync,
   0 if everything went ok. */
int mail_index_fsck(struct mail_index *index);
/* Returns TRUE if mail_index_fsck() has been called since the last
   mail_index_reset_fscked() call. */
bool mail_index_reset_fscked(struct mail_index *index);

/* Synchronize changes in view. You have to go through all records, or view
   will be marked inconsistent. Only sync_mask type records are
   synchronized. */
struct mail_index_view_sync_ctx *
mail_index_view_sync_begin(struct mail_index_view *view,
			   enum mail_index_view_sync_flags flags);
bool mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			       struct mail_index_view_sync_rec *sync_rec);
void
mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
				  const ARRAY_TYPE(seq_range) **expunges_r);
int mail_index_view_sync_commit(struct mail_index_view_sync_ctx **ctx,
				bool *delayed_expunges_r);

/* Returns the index header. */
const struct mail_index_header *
mail_index_get_header(struct mail_index_view *view);
/* Returns the wanted message record. */
const struct mail_index_record *
mail_index_lookup(struct mail_index_view *view, uint32_t seq);
const struct mail_index_record *
mail_index_lookup_full(struct mail_index_view *view, uint32_t seq,
		       struct mail_index_map **map_r);
/* Returns TRUE if the given message has already been expunged from index. */
bool mail_index_is_expunged(struct mail_index_view *view, uint32_t seq);
/* Note that returned keyword indexes aren't sorted. */
void mail_index_lookup_keywords(struct mail_index_view *view, uint32_t seq,
				ARRAY_TYPE(keyword_indexes) *keyword_idx);
/* Return keywords from given map. */
void mail_index_map_lookup_keywords(struct mail_index_map *map, uint32_t seq,
				    ARRAY_TYPE(keyword_indexes) *keyword_idx);
/* mail_index_lookup[_keywords]() returns the latest flag changes.
   This function instead attempts to return the flags and keywords done by the
   last view sync. */
void mail_index_lookup_view_flags(struct mail_index_view *view, uint32_t seq,
				  enum mail_flags *flags_r,
				  ARRAY_TYPE(keyword_indexes) *keyword_idx);
/* Returns the UID for given message. May be slightly faster than
   mail_index_lookup()->uid. */
void mail_index_lookup_uid(struct mail_index_view *view, uint32_t seq,
			   uint32_t *uid_r);
/* Convert UID range to sequence range. If no UIDs are found, returns FALSE and
   sequences are set to 0. Note that any of the returned sequences may have
   been expunged already. */
bool mail_index_lookup_seq_range(struct mail_index_view *view,
				 uint32_t first_uid, uint32_t last_uid,
				 uint32_t *first_seq_r, uint32_t *last_seq_r);
bool mail_index_lookup_seq(struct mail_index_view *view,
			   uint32_t uid, uint32_t *seq_r);
/* Find first mail with (mail->flags & flags_mask) == flags. Useful mostly for
   taking advantage of lowwater-fields in headers. */
void mail_index_lookup_first(struct mail_index_view *view,
			     enum mail_flags flags, uint8_t flags_mask,
			     uint32_t *seq_r);

/* Append a new record to index. */
void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r);
/* Assign new UIDs for mails with uid=0 or uid<min_allowed_uid. All the new
   UIDs are >= first_new_uid, an also higher than the highest seen uid (i.e. it
   doesn't try to fill UID gaps). Assumes that mailbox is locked in a way that
   UIDs can be safely assigned. Returns UIDs for all assigned messages, in
   their sequence order (so UIDs are not necessary ascending). */
void mail_index_append_finish_uids_full(struct mail_index_transaction *t,
					uint32_t min_allowed_uid,
					uint32_t first_new_uid,
					ARRAY_TYPE(seq_range) *uids_r);
/* Call mail_index_append_finish_uids_full() with first_uid used for both
   min_allowed_uid and first_new_uid. */
void mail_index_append_finish_uids(struct mail_index_transaction *t,
				   uint32_t first_uid,
				   ARRAY_TYPE(seq_range) *uids_r);
/* Expunge record from index. Note that this doesn't affect sequence numbers
   until transaction is committed and mailbox is synced. */
void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq);
/* Like mail_index_expunge(), but also write message GUID to transaction log. */
void mail_index_expunge_guid(struct mail_index_transaction *t, uint32_t seq,
			     const guid_128_t guid_128);
/* Revert all changes done in this transaction to the given existing mail. */
void mail_index_revert_changes(struct mail_index_transaction *t, uint32_t seq);
/* Update flags in index. */
void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags);
void mail_index_update_flags_range(struct mail_index_transaction *t,
				   uint32_t seq1, uint32_t seq2,
				   enum modify_type modify_type,
				   enum mail_flags flags);
/* Specified attribute's value was changed. This is just a notification so the
   change gets assigned its own modseq and any log readers can find out about
   this change. */
void mail_index_attribute_set(struct mail_index_transaction *t,
			      bool pvt, const char *key,
			      time_t timestamp, uint32_t value_len);
/* Attribute was deleted. */
void mail_index_attribute_unset(struct mail_index_transaction *t,
				bool pvt, const char *key, time_t timestamp);
/* Update message's modseq to be at least min_modseq. */
void mail_index_update_modseq(struct mail_index_transaction *t, uint32_t seq,
			      uint64_t min_modseq);
/* Update highest modseq to be at least min_modseq. */
void mail_index_update_highest_modseq(struct mail_index_transaction *t,
				      uint64_t min_modseq);
/* Reset the index before committing this transaction. This is usually done
   only when UIDVALIDITY changes. */
void mail_index_reset(struct mail_index_transaction *t);
/* Remove MAIL_INDEX_HDR_FLAG_FSCKD from header if it exists. This must be
   called only during syncing so that the mailbox is locked. */
void mail_index_unset_fscked(struct mail_index_transaction *t);
/* Mark index deleted. No further changes will be possible after the
   transaction has been committed. */
void mail_index_set_deleted(struct mail_index_transaction *t);
/* Mark a deleted index as undeleted. Afterwards index can be changed again. */
void mail_index_set_undeleted(struct mail_index_transaction *t);
/* Returns TRUE if index has been set deleted. This gets set only after
   index has been opened/refreshed and the transaction has been seen. */
bool mail_index_is_deleted(struct mail_index *index);
/* Returns the last time the index was modified. This can be called even if the
   index isn't open. If the index doesn't exist, sets mtime to 0. */
int mail_index_get_modification_time(struct mail_index *index, time_t *mtime_r);

/* Lookup a keyword, returns TRUE if found, FALSE if not. */
bool mail_index_keyword_lookup(struct mail_index *index,
			       const char *keyword, unsigned int *idx_r);
void mail_index_keyword_lookup_or_create(struct mail_index *index,
					 const char *keyword,
					 unsigned int *idx_r);
/* Return a pointer to array of NULL-terminated list of keywords. Note that
   the array contents (and thus pointers inside it) may change after calling
   mail_index_keywords_create() or mail_index_sync_begin(). */
const ARRAY_TYPE(keywords) *mail_index_get_keywords(struct mail_index *index);

/* Create a keyword list structure. */
struct mail_keywords *
mail_index_keywords_create(struct mail_index *index,
			   const char *const keywords[]) ATTR_NULL(2);
struct mail_keywords *
mail_index_keywords_create_from_indexes(struct mail_index *index,
					const ARRAY_TYPE(keyword_indexes)
						*keyword_indexes);
void mail_index_keywords_ref(struct mail_keywords *keywords);
void mail_index_keywords_unref(struct mail_keywords **keywords);

/* Update keywords for given message. */
void mail_index_update_keywords(struct mail_index_transaction *t, uint32_t seq,
				enum modify_type modify_type,
				struct mail_keywords *keywords);

/* Update field in header. If prepend is TRUE, the header change is visible
   before message syncing begins. */
void mail_index_update_header(struct mail_index_transaction *t,
			      size_t offset, const void *data, size_t size,
			      bool prepend);

/* Returns the full error message for last error. This message may
   contain paths etc. so it shouldn't be shown to users. */
const char *mail_index_get_error_message(struct mail_index *index);
/* Reset the error message. */
void mail_index_reset_error(struct mail_index *index);

/* Apply changes in MAIL_INDEX_SYNC_TYPE_FLAGS typed sync records to given
   flags variable. */
void mail_index_sync_flags_apply(const struct mail_index_sync_rec *sync_rec,
				 uint8_t *flags);
/* Apply changes in MAIL_INDEX_SYNC_TYPE_KEYWORD_* typed sync records to given
   keywords array. Returns TRUE If something was changed. */
bool mail_index_sync_keywords_apply(const struct mail_index_sync_rec *sync_rec,
				    ARRAY_TYPE(keyword_indexes) *keywords);

/* register index extension. name is a unique identifier for the extension.
   returns unique identifier for the name. */
uint32_t mail_index_ext_register(struct mail_index *index, const char *name,
				 uint32_t default_hdr_size,
				 uint16_t default_record_size,
				 uint16_t default_record_align);
/* Change an already registered extension's default sizes. */
void mail_index_ext_register_resize_defaults(struct mail_index *index,
					     uint32_t ext_id,
					     uint32_t default_hdr_size,
					     uint16_t default_record_size,
					     uint16_t default_record_align);
/* Returns TRUE and sets ext_id_r if extension with given name is registered. */
bool mail_index_ext_lookup(struct mail_index *index, const char *name,
			   uint32_t *ext_id_r);
/* Resize existing extension data. If size is grown, the new data will be
   zero-filled. If size is shrinked, the data is simply dropped. */
void mail_index_ext_resize(struct mail_index_transaction *t, uint32_t ext_id,
			   uint32_t hdr_size, uint16_t record_size,
			   uint16_t record_align);
/* Resize header, keeping the old record size. */
void mail_index_ext_resize_hdr(struct mail_index_transaction *t,
			       uint32_t ext_id, uint32_t hdr_size);

/* Reset extension. Any updates for this extension which were issued before the
   writer had seen this reset are discarded. reset_id is used to figure this
   out, so it must be different every time. If clear_data=TRUE, records and
   header is zeroed. */
void mail_index_ext_reset(struct mail_index_transaction *t, uint32_t ext_id,
			  uint32_t reset_id, bool clear_data);
/* Like mail_index_ext_reset(), but increase extension's reset_id atomically
   when the transaction is being committed. If prev_reset_id doesn't match the
   latest reset_id, the reset_id isn't increased and all extension changes are
   ignored. */
void mail_index_ext_reset_inc(struct mail_index_transaction *t, uint32_t ext_id,
			      uint32_t prev_reset_id, bool clear_data);
/* Discard existing extension updates in this transaction and write new updates
   using the given reset_id. The difference to mail_index_ext_reset() is that
   this doesn't clear any existing record or header data. */
void mail_index_ext_set_reset_id(struct mail_index_transaction *t,
				 uint32_t ext_id, uint32_t reset_id);
/* Get the current reset_id for given extension. Returns TRUE if it exists. */
bool mail_index_ext_get_reset_id(struct mail_index_view *view,
				 struct mail_index_map *map,
				 uint32_t ext_id, uint32_t *reset_id_r);

/* Returns extension header. */
void mail_index_get_header_ext(struct mail_index_view *view, uint32_t ext_id,
			       const void **data_r, size_t *data_size_r);
void mail_index_map_get_header_ext(struct mail_index_view *view,
				   struct mail_index_map *map, uint32_t ext_id,
				   const void **data_r, size_t *data_size_r);
/* Returns the wanted extension record for given message. If it doesn't exist,
   *data_r is set to NULL. expunged_r is TRUE if the message has already been
   expunged from the index. */
void mail_index_lookup_ext(struct mail_index_view *view, uint32_t seq,
			   uint32_t ext_id, const void **data_r,
			   bool *expunged_r);
void mail_index_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
				uint32_t ext_id, struct mail_index_map **map_r,
				const void **data_r, bool *expunged_r);
/* Get current extension sizes. Returns 1 if ok, 0 if extension doesn't exist
   in view. Any of the _r parameters may be NULL. */
void mail_index_ext_get_size(struct mail_index_map *map, uint32_t ext_id,
			     uint32_t *hdr_size_r, uint16_t *record_size_r,
			     uint16_t *record_align_r);
/* Update extension header field. */
void mail_index_update_header_ext(struct mail_index_transaction *t,
				  uint32_t ext_id, size_t offset,
				  const void *data, size_t size);
/* Update extension record. If old_data_r is non-NULL and the record extension
   was already updated in this transaction, it's set to contain the data it's
   now overwriting. */
void mail_index_update_ext(struct mail_index_transaction *t, uint32_t seq,
			   uint32_t ext_id, const void *data, void *old_data)
	ATTR_NULL(5);
/* Increase/decrease number in extension atomically. Returns the sum of the
   diffs for this seq. */
int mail_index_atomic_inc_ext(struct mail_index_transaction *t,
			      uint32_t seq, uint32_t ext_id, int diff);

#endif
