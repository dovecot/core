#ifndef __MAIL_INDEX_H
#define __MAIL_INDEX_H

#include "mail-types.h"

#define MAIL_INDEX_MAJOR_VERSION 4
#define MAIL_INDEX_MINOR_VERSION 0

#define MAIL_INDEX_HEADER_MIN_SIZE 68

/* Number of keywords in mail_index_record. */
#define INDEX_KEYWORDS_COUNT (3*8)
#define INDEX_KEYWORDS_BYTE_COUNT ((INDEX_KEYWORDS_COUNT+CHAR_BIT-1) / CHAR_BIT)

enum mail_index_open_flags {
	/* Create index if it doesn't exist */
	MAIL_INDEX_OPEN_FLAG_CREATE		= 0x01,
	/* Open the index as fast as possible - do only minimal checks and
	   delay opening cache/log files unless they're needed. */
	MAIL_INDEX_OPEN_FLAG_FAST		= 0x02,
	/* Don't try to mmap() index files */
	MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE	= 0x04,
	/* Don't try to write() to mmap()ed index files. Required for the few
	   OSes that don't have unified buffer cache
	   (currently OpenBSD <= 3.5) */
	MAIL_INDEX_OPEN_FLAG_MMAP_NO_WRITE	= 0x08,
	/* Don't use fcntl() locking */
	MAIL_INDEX_OPEN_FLAG_FCNTL_LOCKS_DISABLE= 0x10
};

enum mail_index_header_compat_flags {
	MAIL_INDEX_COMPAT_LITTLE_ENDIAN		= 0x01
};

enum mail_index_header_flag {
	/* Index file is corrupted, reopen or recreate it. */
	MAIL_INDEX_HDR_FLAG_CORRUPTED		= 0x0001,
	MAIL_INDEX_HDR_FLAG_HAVE_DIRTY		= 0x0002
};

enum mail_index_mail_flags {
	MAIL_INDEX_MAIL_FLAG_DIRTY = 0x80
};

enum mail_index_error {
	/* No errors */
	MAIL_INDEX_ERROR_NONE,
	/* Internal error, see get_error_text() for more information. */
	MAIL_INDEX_ERROR_INTERNAL,
	/* We ran out of available disk space. */
	MAIL_INDEX_ERROR_DISKSPACE
};

#define MAIL_INDEX_FLAGS_MASK \
	(MAIL_ANSWERED | MAIL_FLAGGED | MAIL_DELETED | MAIL_SEEN | MAIL_DRAFT)

typedef unsigned char keywords_mask_t[INDEX_KEYWORDS_BYTE_COUNT];

struct mail_index_header {
	/* major version is increased only when you can't have backwards
	   compatibility. minor version is increased when header size is
	   increased to contain new non-critical fields. */
	uint8_t major_version;
	uint8_t minor_version;
	uint16_t header_size;

	/* 0 = flags
	   1 = sizeof(uoff_t)
	   2 = sizeof(time_t)
	   3 = sizeof(keywords_mask_t) */
	uint8_t compat_data[4];

	uint32_t indexid;
	uint32_t flags;

	uint32_t uid_validity;
	uint32_t next_uid;

	uint32_t messages_count;
	uint32_t seen_messages_count;
	uint32_t deleted_messages_count;

	/* these UIDs may not exist and may not even be unseen */
	uint32_t first_recent_uid_lowwater;
	uint32_t first_unseen_uid_lowwater;
	uint32_t first_deleted_uid_lowwater;

	uint32_t log_file_seq;
	uint32_t log_file_offset;

	uint64_t sync_size;
	uint32_t sync_stamp;

	uint32_t cache_file_seq;
};

struct mail_index_record {
	uint32_t uid;
	uint8_t flags; /* mail_flags | mail_index_mail_flags */
	keywords_mask_t keywords;
	uint32_t cache_offset;
};

enum mail_index_sync_type {
	MAIL_INDEX_SYNC_TYPE_APPEND	= 0x01,
	MAIL_INDEX_SYNC_TYPE_EXPUNGE	= 0x02,
	MAIL_INDEX_SYNC_TYPE_FLAGS	= 0x04
};
#define MAIL_INDEX_SYNC_MASK_ALL 0xff

struct mail_index_sync_rec {
	uint32_t seq1, seq2;
	enum mail_index_sync_type type;

	/* MAIL_INDEX_SYNC_TYPE_FLAGS: */
	uint8_t add_flags;
	keywords_mask_t add_keywords;
	uint8_t remove_flags;
	keywords_mask_t remove_keywords;

	/* MAIL_INDEX_SYNC_TYPE_APPEND: */
        const struct mail_index_record *appends;
};

struct mail_index;
struct mail_index_view;
struct mail_index_transaction;
struct mail_index_sync_ctx;
struct mail_index_view_sync_ctx;

struct mail_index *mail_index_alloc(const char *dir, const char *prefix);
void mail_index_free(struct mail_index *index);

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags);
void mail_index_close(struct mail_index *index);

struct mail_cache *mail_index_get_cache(struct mail_index *index);

/* View can be used to look into index. Sequence numbers inside view change
   only when you synchronize it. The view acquires required locks
   automatically, but you'll have to drop them manually. Opening view
   acquires a lock immediately. */
struct mail_index_view *mail_index_view_open(struct mail_index *index);
void mail_index_view_close(struct mail_index_view *view);

/* Returns the index for given view. */
struct mail_index *mail_index_view_get_index(struct mail_index_view *view);
/* Call whenever you've done with requesting messages from view for a while. */
void mail_index_view_unlock(struct mail_index_view *view);
/* Returns number of mails in view. */
uint32_t mail_index_view_get_message_count(struct mail_index_view *view);
/* Returns TRUE if we lost track of changes for some reason. */
int mail_index_view_is_inconsistent(struct mail_index_view *view);

/* Transaction has to be opened to be able to modify index. You can have
   multiple transactions open simultaneously. Note that committed transactions
   won't show up until you've synchronized mailbox (mail_index_sync_begin). */
struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view, int hide);
int mail_index_transaction_commit(struct mail_index_transaction *t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r);
void mail_index_transaction_rollback(struct mail_index_transaction *t);

/* Begin synchronizing mailbox with index file. This call locks the index
   exclusively against other modifications. Returns 1 if ok, -1 if error.

   If log_file_seq is not (uint32_t)-1 and index is already synchronized up
   to given log_file_offset, the synchronization isn't started and this
   function returns 0. This should be done when you wish to sync your previous
   transaction instead of doing a full mailbox synchronization.

   mail_index_sync_next() returns all changes from previously committed
   transactions which haven't yet been committed to the actual mailbox.
   They're returned in ascending order. You must go through all of them and
   update the mailbox accordingly.

   None of the changes actually show up in index until at
   mail_index_sync_end().

   Note that there may be multiple overlapping flag changes. They're returned
   sorted by their beginning sequence. They never overlap expunges however.
   Returned sequence numbers describe the mailbox state at the beginning of
   synchronization, ie. expunges don't affect them.

   You may create a new transaction for the returned view. That transaction
   acts as "external mailbox changes" transaction. Any changes done there are
   expected to describe mailbox's current state. */
int mail_index_sync_begin(struct mail_index *index,
			  struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  uint32_t log_file_seq, uoff_t log_file_offset);
/* Returns -1 if error, 0 if sync is finished, 1 if record was filled. */
int mail_index_sync_next(struct mail_index_sync_ctx *ctx,
			 struct mail_index_sync_rec *sync_rec);
/* Returns 1 if there's more to sync, 0 if not. */
int mail_index_sync_have_more(struct mail_index_sync_ctx *ctx);
/* Mark given message to be dirty, ie. we couldn't temporarily change the
   message flags in storage. Dirty messages are tried to be synced again in
   next sync. */
int mail_index_sync_set_dirty(struct mail_index_sync_ctx *ctx, uint32_t seq);
/* End synchronization by unlocking the index and closing the view.
   sync_stamp/sync_size in header is updated to given values. */
int mail_index_sync_end(struct mail_index_sync_ctx *ctx,
			uint32_t sync_stamp, uint64_t sync_size);

/* Mark index file corrupted. Invalidates all views. */
void mail_index_mark_corrupted(struct mail_index *index);
/* Check and fix any found problems. If index is broken beyond repair, calls
   mail_index_reset() and returns 0. Otherwise returns -1 if there was some
   I/O error or 1 if everything went ok. */
int mail_index_fsck(struct mail_index *index);

/* Synchronize changes in view. You have to go through all records, or view
   will be marked inconsistent. Only sync_mask type records are
   synchronized. */
int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_sync_type sync_mask,
			       struct mail_index_view_sync_ctx **ctx_r);
/* Returns -1 if error, 0 if sync is finished, 1 if record was filled. */
int mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			      struct mail_index_sync_rec *sync_rec);
const uint32_t *
mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
				 size_t *count_r);
void mail_index_view_sync_end(struct mail_index_view_sync_ctx *ctx);

/* Returns the index header. */
int mail_index_get_header(struct mail_index_view *view,
			  const struct mail_index_header **hdr_r);
/* Returns the given message. */
int mail_index_lookup(struct mail_index_view *view, uint32_t seq,
		      const struct mail_index_record **rec_r);
/* Returns the UID for given message. May be slightly faster than
   mail_index_lookup()->uid */
int mail_index_lookup_uid(struct mail_index_view *view, uint32_t seq,
			  uint32_t *uid_r);
/* Convert UID range to sequence range. If no UIDs are found, sequences are
   set to 0. Note that any of the returned sequences may have been expunged
   already. */
int mail_index_lookup_uid_range(struct mail_index_view *view,
				uint32_t first_uid, uint32_t last_uid,
				uint32_t *first_seq_r, uint32_t *last_seq_r);
/* Find first mail with (mail->flags & flags_mask) == flags. Useful mostly for
   taking advantage of lowwater-fields in headers. */
int mail_index_lookup_first(struct mail_index_view *view, enum mail_flags flags,
			    uint8_t flags_mask, uint32_t *seq_r);

/* Append a new record to index. */
void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r);
/* Expunge record from index. Note that this doesn't affect sequence numbers
   until transaction is committed and mailbox is synced. */
void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq);
/* Update flags in index. */
void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags, keywords_mask_t keywords);

/* Returns the last error code. */
enum mail_index_error mail_index_get_last_error(struct mail_index *index);
/* Returns the full error message for last error. This message may
   contain paths etc. so it shouldn't be shown to users. */
const char *mail_index_get_error_message(struct mail_index *index);
/* Reset the error message. */
void mail_index_reset_error(struct mail_index *index);

/* Returns TRUE if index is currently only in memory. */
int mail_index_is_in_memory(struct mail_index *index);

/* Apply changes in MAIL_INDEX_SYNC_TYPE_FLAGS typed sync records to given
   flags variables. */
void mail_index_sync_flags_apply(const struct mail_index_sync_rec *sync_rec,
				 uint8_t *flags, keywords_mask_t keywords);

#endif
