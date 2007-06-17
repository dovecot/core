#ifndef __MAIL_INDEX_H
#define __MAIL_INDEX_H

#include "mail-types.h"
#include "seq-range-array.h"

#define MAIL_INDEX_MAJOR_VERSION 7
#define MAIL_INDEX_MINOR_VERSION 1

#define MAIL_INDEX_HEADER_MIN_SIZE 120

enum file_lock_method;

enum mail_index_open_flags {
	/* Create index if it doesn't exist */
	MAIL_INDEX_OPEN_FLAG_CREATE		= 0x01,
	/* Don't try to mmap() index files */
	MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE	= 0x04,
	/* Rely on O_EXCL when creating dotlocks */
	MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL	= 0x10,
	/* Don't fsync() or fdatasync() */
	MAIL_INDEX_OPEN_FLAG_FSYNC_DISABLE	= 0x20
};

enum mail_index_header_compat_flags {
	MAIL_INDEX_COMPAT_LITTLE_ENDIAN		= 0x01
};

enum mail_index_header_flag {
	/* Index file is corrupted, reopen or recreate it. */
	MAIL_INDEX_HDR_FLAG_CORRUPTED		= 0x0001,
	MAIL_INDEX_HDR_FLAG_HAVE_DIRTY		= 0x0002,
	/* fsck the index next time when opening */
	MAIL_INDEX_HDR_FLAG_FSCK		= 0x0004
};

enum mail_index_mail_flags {
	MAIL_INDEX_MAIL_FLAG_DIRTY = 0x80
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
	uint32_t recent_messages_count;
	uint32_t seen_messages_count;
	uint32_t deleted_messages_count;

	/* these UIDs may not exist and may not even be unseen */
	uint32_t first_recent_uid_lowwater;
	uint32_t first_unseen_uid_lowwater;
	uint32_t first_deleted_uid_lowwater;

	uint32_t log_file_seq;
	/* non-external records between tail..head haven't been committed to
	   mailbox yet. */
	uint32_t log_file_tail_offset;
	uint32_t log_file_head_offset;

	uint64_t sync_size;
	uint32_t sync_stamp;

	/* daily first UIDs that have been added to index. */
	uint32_t day_stamp;
	uint32_t day_first_uid[8];
};

struct mail_index_record {
	uint32_t uid;
	uint8_t flags; /* enum mail_flags | enum mail_index_mail_flags */
};

struct mail_keywords {
	struct mail_index *index;
	unsigned int count;

        /* variable sized list of keyword indexes */
	unsigned int idx[1];
};

enum mail_index_sync_type {
	MAIL_INDEX_SYNC_TYPE_APPEND		= 0x01,
	MAIL_INDEX_SYNC_TYPE_EXPUNGE		= 0x02,
	MAIL_INDEX_SYNC_TYPE_FLAGS		= 0x04,
	MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD	= 0x08,
	MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE	= 0x10,
	MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET	= 0x20
};

enum mail_index_view_sync_flags {
	/* Don't sync expunges */
	MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES
};

struct mail_index_sync_rec {
	uint32_t uid1, uid2;
	enum mail_index_sync_type type;

	/* MAIL_INDEX_SYNC_TYPE_FLAGS: */
	uint8_t add_flags;
	uint8_t remove_flags;

	/* MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD, .._REMOVE: */
	unsigned int keyword_idx;
};

struct mail_index_view_sync_rec {
	uint32_t uid1, uid2;
	/* keyword appends and removes are packed into one and same
	   MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD */
	enum mail_index_sync_type type;
};

ARRAY_DEFINE_TYPE(keyword_indexes, unsigned int);

struct mail_index;
struct mail_index_map;
struct mail_index_view;
struct mail_index_transaction;
struct mail_index_sync_ctx;
struct mail_index_view_sync_ctx;

struct mail_index *mail_index_alloc(const char *dir, const char *prefix);
void mail_index_free(struct mail_index **index);

void mail_index_set_permissions(struct mail_index *index,
				mode_t mode, gid_t gid);

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags,
		    enum file_lock_method lock_method);
void mail_index_close(struct mail_index *index);

/* Move the index into memory. Returns 0 if ok, -1 if error occurred. */
int mail_index_move_to_memory(struct mail_index *index);

struct mail_cache *mail_index_get_cache(struct mail_index *index);

/* Refresh index so mail_index_lookup*() will return latest values. Note that
   immediately after this call there may already be changes, so if you need to
   rely on validity of the returned values, use some external locking for it. */
int mail_index_refresh(struct mail_index *index);

/* View can be used to look into index. Sequence numbers inside view change
   only when you synchronize it. The view acquires required locks
   automatically, but you'll have to drop them manually. */
struct mail_index_view *mail_index_view_open(struct mail_index *index);
void mail_index_view_close(struct mail_index_view **view);

/* Returns the index for given view. */
struct mail_index *mail_index_view_get_index(struct mail_index_view *view);
/* Call whenever you've done with requesting messages from view for a while. */
void mail_index_view_unlock(struct mail_index_view *view);
/* Returns number of mails in view. */
uint32_t mail_index_view_get_messages_count(struct mail_index_view *view);
/* Returns TRUE if we lost track of changes for some reason. */
bool mail_index_view_is_inconsistent(struct mail_index_view *view);

/* Transaction has to be opened to be able to modify index. You can have
   multiple transactions open simultaneously. Committed transactions won't
   show up until you've synchronized the view. Expunges won't show up until
   you've synchronized the mailbox (mail_index_sync_begin).

   If transaction is marked as hidden, the changes won't be listed when the
   view is synchronized. Expunges can't be hidden.

   External transactions describe changes to mailbox that have already
   happened. */
struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     bool hide, bool external);
int mail_index_transaction_commit(struct mail_index_transaction **t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r);
void mail_index_transaction_rollback(struct mail_index_transaction **t);
/* Discard all changes in the transaction. */
void mail_index_transaction_reset(struct mail_index_transaction *t);

/* Returns the view transaction was created for. */
struct mail_index_view *
mail_index_transaction_get_view(struct mail_index_transaction *t);
/* Returns TRUE if the given sequence is being expunged in this transaction. */
bool mail_index_transaction_is_expunged(struct mail_index_transaction *t,
					uint32_t seq);

/* Returns a view to transaction. Currently this differs from normal view only
   in that it contains newly appended messages in transaction. The view can
   still be used after transaction has been committed. */
struct mail_index_view *
mail_index_transaction_open_updated_view(struct mail_index_transaction *t);

/* Begin synchronizing mailbox with index file. Returns 1 if ok, -1 if error.

   If log_file_seq is not (uint32_t)-1 and index is already synchronized up
   to the given log_file_offset, the synchronization isn't started and this
   function returns 0. This should be done when you wish to sync your committed
   transaction instead of doing a full mailbox synchronization.

   mail_index_sync_next() returns all changes from previously committed
   transactions which haven't yet been committed to the actual mailbox.
   They're returned in ascending order and they never overlap (if we add more
   sync types, then they might). You must go through all of them and update
   the mailbox accordingly.

   None of the changes actually show up in the index until after a successful
   mail_index_sync_commit().

   Returned sequence numbers describe the mailbox state at the beginning of
   synchronization, ie. expunges don't affect them.

   Changes done to the returned transaction are expected to describe the
   mailbox's current state. */
int mail_index_sync_begin(struct mail_index *index,
			  struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  struct mail_index_transaction **trans_r,
			  uint32_t log_file_seq, uoff_t log_file_offset,
			  bool sync_recent, bool sync_dirty);
/* Returns -1 if error, 0 if sync is finished, 1 if record was filled. */
int mail_index_sync_next(struct mail_index_sync_ctx *ctx,
			 struct mail_index_sync_rec *sync_rec);
/* Returns TRUE if there's more to sync. */
bool mail_index_sync_have_more(struct mail_index_sync_ctx *ctx);
/* Reset syncing to initial state after mail_index_sync_begin(), so you can
   go through all the sync records again with mail_index_sync_next(). */
void mail_index_sync_reset(struct mail_index_sync_ctx *ctx);
/* Commit synchronization by writing all changes to mail index file. */
int mail_index_sync_commit(struct mail_index_sync_ctx **ctx);
/* Rollback synchronization - none of the changes listed by sync_next() are
   actually written to index file. */
void mail_index_sync_rollback(struct mail_index_sync_ctx **ctx);

/* Mark index file corrupted. Invalidates all views. */
void mail_index_mark_corrupted(struct mail_index *index);
/* Check and fix any found problems. If index is broken beyond repair, it's
   marked corrupted and 0 is returned. Otherwise returns -1 if there was some
   I/O error or 1 if everything went ok. */
int mail_index_fsck(struct mail_index *index);

/* Synchronize changes in view. You have to go through all records, or view
   will be marked inconsistent. Only sync_mask type records are
   synchronized. */
int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_view_sync_flags flags,
			       struct mail_index_view_sync_ctx **ctx_r);
/* Returns -1 if error, 0 if sync is finished, 1 if record was filled. */
int mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			      struct mail_index_view_sync_rec *sync_rec);
void
mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
				  const ARRAY_TYPE(seq_range) **expunges_r);
void mail_index_view_sync_end(struct mail_index_view_sync_ctx **ctx);

/* Returns the index header. */
const struct mail_index_header *
mail_index_get_header(struct mail_index_view *view);
/* Returns the given message. Returns -1 if error, 1 if ok, 0 if mail was
   expunged but data was returned from some older index.  */
int mail_index_lookup(struct mail_index_view *view, uint32_t seq,
		      const struct mail_index_record **rec_r);
int mail_index_lookup_full(struct mail_index_view *view, uint32_t seq,
			   struct mail_index_map **map_r,
			   const struct mail_index_record **rec_r);
/* Note that returned keyword indexes aren't sorted. */
int mail_index_lookup_keywords(struct mail_index_view *view, uint32_t seq,
			       ARRAY_TYPE(keyword_indexes) *keyword_idx);
/* Returns the UID for given message. May be slightly faster than
   mail_index_lookup()->uid. */
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
/* Assigns UIDs for appended mails all at once. UID must have been given as 0
   for mail_index_append(). Returns the next unused UID. */
void mail_index_append_assign_uids(struct mail_index_transaction *t,
				   uint32_t first_uid, uint32_t *next_uid_r);
/* Expunge record from index. Note that this doesn't affect sequence numbers
   until transaction is committed and mailbox is synced. */
void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq);
/* Update flags in index. */
void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags);
void mail_index_update_flags_range(struct mail_index_transaction *t,
				   uint32_t seq1, uint32_t seq2,
				   enum modify_type modify_type,
				   enum mail_flags flags);

/* Lookup a keyword, returns TRUE if found, FALSE if not. If autocreate is
   TRUE, the keyword is automatically created and TRUE is always returned. */
bool mail_index_keyword_lookup(struct mail_index *index,
			       const char *keyword, bool autocreate,
			       unsigned int *idx_r);
/* Return a pointer to array of NULL-terminated list of keywords. Note that
   the array contents (and thus pointers inside it) may change after calling
   mail_index_keywords_create() or mail_index_sync_begin(). */
const ARRAY_TYPE(keywords) *mail_index_get_keywords(struct mail_index *index);

/* Create a keyword list structure. It's freed automatically at the end of
   the transaction. */
struct mail_keywords *
mail_index_keywords_create(struct mail_index_transaction *t,
			   const char *const keywords[]);
struct mail_keywords *
mail_index_keywords_create_from_indexes(struct mail_index_transaction *t,
					const ARRAY_TYPE(keyword_indexes)
						*keyword_indexes);
/* Free the keywords. */
void mail_index_keywords_free(struct mail_keywords **keywords);
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
/* Resize existing extension data. If size is grown, the new data will be
   zero-filled. If size is shrinked, the data is simply dropped. */
void mail_index_ext_resize(struct mail_index_transaction *t, uint32_t ext_id,
			   uint32_t hdr_size, uint16_t record_size,
			   uint16_t record_align);

/* Reset extension records and header. Any updates for this extension which
   were issued before the writer had seen this reset are discarded. reset_id is
   used to figure this out, so it must be different every time. */
void mail_index_ext_reset(struct mail_index_transaction *t, uint32_t ext_id,
			  uint32_t reset_id);

/* Returns extension header. */
int mail_index_get_header_ext(struct mail_index_view *view, uint32_t ext_id,
			      const void **data_r, size_t *data_size_r);
int mail_index_map_get_header_ext(struct mail_index_view *view,
				  struct mail_index_map *map, uint32_t ext_id,
				  const void **data_r, size_t *data_size_r);
/* Returns the wanted extension record for given message. If it doesn't exist,
   *data_r is set to NULL. Return values are same as for mail_index_lookup(). */
int mail_index_lookup_ext(struct mail_index_view *view, uint32_t seq,
			  uint32_t ext_id, const void **data_r);
int mail_index_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
			       uint32_t ext_id, struct mail_index_map **map_r,
			       const void **data_r);
/* Get current extension sizes. Returns 1 if ok, 0 if extension doesn't exist
   in view. Any of the _r parameters may be NULL. */
int mail_index_ext_get_size(struct mail_index_view *view,
			    uint32_t ext_id, struct mail_index_map *map,
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
			   uint32_t ext_id, const void *data, void *old_data);

#endif
