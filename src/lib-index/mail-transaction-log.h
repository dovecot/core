#ifndef MAIL_TRANSACTION_LOG_H
#define MAIL_TRANSACTION_LOG_H

#include "mail-index.h"

#define MAIL_TRANSACTION_LOG_SUFFIX ".log"

#define MAIL_TRANSACTION_LOG_MAJOR_VERSION 1
#define MAIL_TRANSACTION_LOG_MINOR_VERSION 3
/* Minimum allowed mail_transaction_log_header.hdr_size. If it's smaller,
   assume the file is corrupted. */
#define MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE 24

/* Helper macro for other MAIL_TRANSACTION_LOG_VERSION_*() macros */
#define MAIL_TRANSACTION_LOG_VERSION_FULL(major, minor) \
	((major) << 8 | (minor))
/* Returns TRUE if the transaction log version supports the given feature.
   The wanted_feature is one of the MAIL_TRANSACTION_LOG_VERSION_FEATURE_*
   macros without the macro prefix, e.g. just COMPAT_FLAGS. */
#define MAIL_TRANSACTION_LOG_VERSION_HAVE(version, wanted_feature) \
	((version) >= MAIL_TRANSACTION_LOG_VERSION_FEATURE_##wanted_feature)
/* Returns transaction log version from the given mail_transaction_log_header
   which is compatible for the MAIL_TRANSACTION_LOG_VERSION_HAVE() macro. */
#define MAIL_TRANSACTION_LOG_HDR_VERSION(hdr) \
	MAIL_TRANSACTION_LOG_VERSION_FULL((hdr)->major_version, (hdr)->minor_version)

/* Log feature: mail_transaction_log_header.compat_flags is filled. */
#define MAIL_TRANSACTION_LOG_VERSION_FEATURE_COMPAT_FLAGS \
	MAIL_TRANSACTION_LOG_VERSION_FULL(1, 2)
/* Log feature: Don't increase modseq when reading internal flag updates
   (because they're not client-visible anyway).
   See MAIL_TRANSACTION_FLAG_UPDATE_IS_INTERNAL(). */
#define MAIL_TRANSACTION_LOG_VERSION_FEATURE_HIDE_INTERNAL_MODSEQS \
	MAIL_TRANSACTION_LOG_VERSION_FULL(1, 3)

struct mail_transaction_log_header {
	/* Major version is increased only when you can't have backwards
	   compatibility. If the field doesn't match
	   MAIL_TRANSACTION_LOG_MAJOR_VERSION, don't even try to read it. */
	uint8_t major_version;
	/* Minor version is increased when the file format changes in a
	   backwards compatible way. */
	uint8_t minor_version;
	/* Size of the header. If it's larger than this struct, ignore any
	   unknown fields. If it's smaller, assume the rest of the fields
	   are 0. */
	uint16_t hdr_size;

	/* Unique index file ID, which must match the main index's indexid.
	   See mail_index_header.indexid. This is overwritten to be 0 if the
	   log file is marked as corrupted. */
	uint32_t indexid;
	/* Log file sequence number. Increased every time the log is rotated
	   and a new log is created. Using (file_seq, offset) uniquely
	   identifies a position in the transaction log. */
	uint32_t file_seq;
	/* The previous log file's sequence and offset when the log was
	   rotated. The offset should be the same as the previous log file's
	   size. If there was no previous log file, or if the index is being
	   reset, these are 0.

	   These are mainly useful to optimize syncing when the start position
	   is (prev_file_seq, prev_file_offset). Then it's it's already known
	   that the syncing can be started from this log file wihtout having
	   to open the previous log file only to realize that there is nothing
	   to sync. (Which could have also lead to an error if the .log.2 was
	   already deleted.) */
	uint32_t prev_file_seq;
	uint32_t prev_file_offset;
	/* UNIX timestamp when this file was created. Used in determining when
	   to rotate the log file. */
	uint32_t create_stamp;
	/* Modseq value at the beginning of this file. Some transaction records
	   increase the modseq value. (Only with log format v1.1+) */
	uint64_t initial_modseq;

	/* Same as enum mail_index_header_compat_flags. Needs
	   MAIL_TRANSACTION_LOG_VERSION_FEATURE_COMPAT_FLAGS. */
	uint8_t compat_flags;
	/* Unused fields to make the struct 64bit aligned. These can be used
	   to add more fields to the header. */
	uint8_t unused[3];
	uint32_t unused2;
};

enum mail_transaction_type {
	/* struct mail_transaction_expunge[] - Expunge the UIDs.
	   Must have MAIL_TRANSACTION_EXPUNGE_PROT ORed to this. Avoid using
	   this, use MAIL_TRANSACTION_EXPUNGE_GUID instead. */
	MAIL_TRANSACTION_EXPUNGE		= 0x00000001,
	/* struct mail_index_record[] - Save new mails with given flags. */
	MAIL_TRANSACTION_APPEND			= 0x00000002,
	/* struct mail_transaction_flag_update[] - Update message flags
	   (or just modseq). */
	MAIL_TRANSACTION_FLAG_UPDATE		= 0x00000004,
	/* struct mail_transaction_header_update[] - Update the index's base
	   header (struct mail_index_header). */
	MAIL_TRANSACTION_HEADER_UPDATE		= 0x00000020,
	/* struct mail_transaction_ext_intro - Start operations for the given
	   extension. This can be used to create a new extension or resize an
	   existing extension, but usually it is just used in front of the
	   other MAIL_TRANSACTION_EXT_* records to specify which extension
	   they're working with. */
	MAIL_TRANSACTION_EXT_INTRO		= 0x00000040,
	/* struct mail_transaction_ext_reset - Reset the last intro extension
	   by changing its reset_id and optionally zeroing out its old data. */
	MAIL_TRANSACTION_EXT_RESET		= 0x00000080,
	/* struct mail_transaction_ext_hdr_update[] - Update the last intro
	   extension's header. This might later become deprecated in favor of
	   supporting only MAIL_TRANSACTION_EXT_HDR_UPDATE32, but for now
	   it's still used for <64kB headers. */
	MAIL_TRANSACTION_EXT_HDR_UPDATE		= 0x00000100,
	/* struct mail_transaction_ext_rec_update[] - Update the last intro
	   extension records for the given UIDs with given content. */
	MAIL_TRANSACTION_EXT_REC_UPDATE		= 0x00000200,
	/* struct mail_transaction_keyword_update - Add/remove the specified
	   keyword to messages. */
	MAIL_TRANSACTION_KEYWORD_UPDATE		= 0x00000400,
	/* struct mail_transaction_keyword_reset[] - Clear out all keywords
	   in specified messages. */
	MAIL_TRANSACTION_KEYWORD_RESET		= 0x00000800,
	/* struct mail_transaction_ext_atomic_inc[] - Atomically increase or
	   decrease the last intro extension record. The record must be 1, 2,
	   4 or 8 bytes. This can be used e.g. for refcount extensions. */
	MAIL_TRANSACTION_EXT_ATOMIC_INC		= 0x00001000,
	/* struct mail_transaction_expunge_guid[] - Expunge given UID, but
	   first verify that it matches the given GUID. Must have
	   MAIL_TRANSACTION_EXPUNGE_PROT ORed to this. */
	MAIL_TRANSACTION_EXPUNGE_GUID		= 0x00002000,
	MAIL_TRANSACTION_MODSEQ_UPDATE		= 0x00008000,
	/* struct mail_transaction_ext_hdr_update32[] - Update the last intro
	   extension's header. Used for >=64kB headers. See also
	   MAIL_TRANSACTION_EXT_HDR_UPDATE. This was added in Dovecot v2.0. */
	MAIL_TRANSACTION_EXT_HDR_UPDATE32	= 0x00010000,
	/* Index was marked as deleted using mail_index_set_deleted().
	   There is no record content for this. */
	MAIL_TRANSACTION_INDEX_DELETED		= 0x00020000,
	/* Index was marked as undeleted using mail_index_set_undeleted().
	   There is no record content for this. */
	MAIL_TRANSACTION_INDEX_UNDELETED	= 0x00040000,
	/* struct mail_transaction_boundary - Specifies a size of the following
	   records that must be treated as a single transaction. This works
	   so that the transaction log reading code stops if it finds that
	   there is a transaction whose size points outside the currently
	   existing file. An unfinished transaction is truncated away after the
	   next write to the log. FIXME: it would be better to rotate the
	   log instead of truncating it. */
	MAIL_TRANSACTION_BOUNDARY		= 0x00080000,
	/* Mailbox attribute update. This is a bit complicated format:
	    - [+-][p-s]<name><NUL>
		- "+" means attribute is set, "-" means unset
		- "p" means private attribute, "s" means shared
		- <name> is the attribute name
		- This can repeat multiple times
	    - <NUL>
	    - 0..3 bytes padding for 32bit alignment
	    - For each attribute update an array of uint32_t integers:
	        - Update timestamp
		- For each "+" only: Length of the attribute value.
	   */
	MAIL_TRANSACTION_ATTRIBUTE_UPDATE       = 0x00100000,

	/* Mask to get the attribute type only (excluding flags). */
	MAIL_TRANSACTION_TYPE_MASK		= 0x0fffffff,

#define MAIL_TRANSACTION_EXT_MASK \
	(MAIL_TRANSACTION_EXT_INTRO | MAIL_TRANSACTION_EXT_RESET | \
	MAIL_TRANSACTION_EXT_HDR_UPDATE | MAIL_TRANSACTION_EXT_HDR_UPDATE32 | \
	MAIL_TRANSACTION_EXT_REC_UPDATE | MAIL_TRANSACTION_EXT_ATOMIC_INC)

	/* Since we'll expunge mails based on data read from transaction log,
	   try to avoid the possibility of corrupted transaction log expunging
	   messages. This value is ORed to the actual MAIL_TRANSACTION_EXPUNGE*
	   flag. If it's not present, assume corrupted log. */
	MAIL_TRANSACTION_EXPUNGE_PROT		= 0x0000cd90,

	/* External transactions have a bit different meanings depending on the
	   transaction type. Generally they mean to indicate changes that have
	   already occurred, instead of changes that are only being requested
	   to happen on next sync. For example expunges are first requested
	   to be done with internal transactions, and then there's a separate
	   external transaction to indicate that they were actually done. */
	MAIL_TRANSACTION_EXTERNAL		= 0x10000000,
	/* This change syncs the state with another mailbox (dsync),
	   i.e. the change isn't something that a user requested locally. */
	MAIL_TRANSACTION_SYNC			= 0x20000000
};

struct mail_transaction_header {
	/* Size of this header and the following records. This size can be
	   used to calculate how many records there are. The size is written
	   via mail_index_uint32_to_offset(). */
	uint32_t size;
	uint32_t type; /* enum mail_transaction_type */
	/* Header is followed by the type-specific records. */
};

/* See MAIL_TRANSACTION_MODSEQ_UPDATE. */
struct mail_transaction_modseq_update {
	uint32_t uid;
	/* don't use uint64_t here. it adds extra 32 bits of padding and also
	   causes problems with CPUs that require alignment */
	uint32_t modseq_low32;
	uint32_t modseq_high32;
};

/* See MAIL_TRANSACTION_EXPUNGE. */
struct mail_transaction_expunge {
	/* Expunge all mails between uid1..uid2. */
	uint32_t uid1, uid2;
};
/* See MAIL_TRANSACTION_EXPUNGE_GUID. */
struct mail_transaction_expunge_guid {
	/* Expunge uid, but only if it matches guid_128. */
	uint32_t uid;
	/* GUID of the mail. If it's not 128 bit GUID, first pass it through
	   mail_generate_guid_128_hash() to get 128 bit SHA1 of it. */
	guid_128_t guid_128;
};

/* See MAIL_TRANSACTION_FLAG_UPDATE. */
struct mail_transaction_flag_update {
	/* Change the flags for all mails between uid1..uid2. */
	uint32_t uid1, uid2;
	/* Add these flags to the mails. */
	uint8_t add_flags;
	/* Remove these flags to the mails. To replace all existing flags,
	   just set this to 0xff and specify the wanted flags in add_flags. */
	uint8_t remove_flags;
	/* If non-0, MAIL_INDEX_MAIL_FLAG_UPDATE_MODSEQ was used to force
	   increasing modseq update to the mails even though no flags were
	   actually changed. This differs from MAIL_TRANSACTION_MODSEQ_UPDATE
	   in that the modseq is just wanted to be increased, doesn't matter
	   to which value specifically. */
	uint8_t modseq_inc_flag;
	/* Unused padding */
	uint8_t padding;
};

/* See MAIL_TRANSACTION_KEYWORD_UPDATE. */
struct mail_transaction_keyword_update {
	/* enum modify_type : MODIFY_ADD / MODIFY_REMOVE */
	uint8_t modify_type;
	uint8_t padding;
	/* Size of name[] */
	uint16_t name_size;
	/* unsigned char name[name_size]; */
	/* Update keywords for the given UIDs. The array's size is calculated
	   from mail_transaction_header.size. */
	/* array of { uint32_t uid1, uid2; } */
};

/* See MAIL_TRANSACTION_KEYWORD_RESET. */
struct mail_transaction_keyword_reset {
	/* Clear out all keywords for uid1..uid2. */
	uint32_t uid1, uid2;
};

/* See MAIL_TRANSACTION_HEADER_UPDATE. */
struct mail_transaction_header_update {
	/* Update start offset. */
	uint16_t offset;
	/* Size of the following data[] to update. */
	uint16_t size;
	/* unsigned char data[size]; */
	/* 0..3 bytes of padding to get to 32bit alignment. */
	/* unsigned char padding[]; */
};

enum {
	/* Don't shrink hdr_size, record_size or record_align but grow them
	   if necessary. */
	MAIL_TRANSACTION_EXT_INTRO_FLAG_NO_SHRINK = 0x01
};

/* See MAIL_TRANSACTION_EXT_INTRO. Also see struct mail_index_ext_header for
   more explanations of these fields. */
struct mail_transaction_ext_intro {
	/* If extension is already known to exist in the index file,
	   set ext_id, but use empty name. If this is a new extension, set
	   name, but use ext_id=(uint32_t)-1. */
	uint32_t ext_id;
	uint32_t reset_id;
	/* Size of the extension header. When growing the header size, it's
	   initially filled with zeros. The header can be written to with
	   ext-hdr-update records. */
	uint32_t hdr_size;
	uint16_t record_size;
	uint16_t record_align;
	uint16_t flags;
	uint16_t name_size;
	/* unsigned char name[]; */
};

/* See MAIL_TRANSACTION_EXT_RESET. */
struct mail_transaction_ext_reset {
	/* New value for extension's reset_id */
	uint32_t new_reset_id;
	/* Non-0 if the old extension header and record data should be
	   preserved. Normally all of it is zeroed out. */
	uint8_t preserve_data;
	uint8_t unused_padding[3];
};

/* See MAIL_TRANSACTION_EXT_HDR_UPDATE. */
struct mail_transaction_ext_hdr_update {
	/* Update start offset. */
	uint16_t offset;
	/* Size of the following data[] to update. */
	uint16_t size;
	/* unsigned char data[size]; */
	/* 0..3 bytes of padding to get to 32bit alignment. */
	/* unsigned char padding[]; */
};
/* See MAIL_TRANSACTION_EXT_HDR_UPDATE32. */
struct mail_transaction_ext_hdr_update32 {
	/* Update start offset. */
	uint32_t offset;
	/* Size of the following data[] to update. */
	uint32_t size;
	/* unsigned char data[size]; */
	/* 0..3 bytes of padding to get to 32bit alignment. */
	/* unsigned char padding[]; */
};

/* See MAIL_TRANSACTION_EXT_REC_UPDATE. */
struct mail_transaction_ext_rec_update {
	uint32_t uid;
	/* unsigned char data[mail_transaction_ext_intro.record_size]; */
	/* 0..3 bytes of padding to get to 32bit alignment. */
	/* unsigned char padding[]; */
};

/* See MAIL_TRANSACTION_EXT_ATOMIC_INC. */
struct mail_transaction_ext_atomic_inc {
	uint32_t uid;
	/* Add this value to the extension record data. Can be negative. */
	int32_t diff;
};

/* See MAIL_TRANSACTION_BOUNDARY. */
struct mail_transaction_boundary {
	/* Size of the whole transaction, including this record and header. */
	uint32_t size;
};

struct mail_transaction_log_append_ctx {
	struct mail_transaction_log *log;
	/* All the changes that will be written to the transaction log. */
	buffer_t *output;

	/* Transaction flags as given to mail_transaction_log_append_begin(). */
	enum mail_transaction_type trans_flags;

	/* Tracking the current highest_modseq after the changes. This will
	   be used to update mail_transaction_log_file.sync_highest_modseq. */
	uint64_t new_highest_modseq;
	/* Number of transaction records added so far. */
	unsigned int transaction_count;

	/* Copied from mail_index_transaction.sync_transaction */
	bool index_sync_transaction:1;
	/* Copied from mail_index_transaction.tail_offset_changed */
	bool tail_offset_changed:1;
	/* TRUE if the mail_transaction_log_file has been synced up to the
	   current write offset, and we're writing a syncing transaction
	   (index_sync_transaction=TRUE). This means that the just written
	   transaction can be assumed to be synced already. */
	bool sync_includes_this:1;
	/* fdatasync() after writing the transaction. */
	bool want_fsync:1;
};

#define LOG_IS_BEFORE(seq1, offset1, seq2, offset2) \
	(((offset1) < (offset2) && (seq1) == (seq2)) || (seq1) < (seq2))

struct mail_transaction_log *
mail_transaction_log_alloc(struct mail_index *index);
void mail_transaction_log_free(struct mail_transaction_log **log);

/* Open the transaction log. Returns 1 if ok, 0 if file doesn't exist or it's
   is corrupted, -1 if there was some I/O error. */
int mail_transaction_log_open(struct mail_transaction_log *log);
/* Create, or recreate, the transaction log. Returns 0 if ok, -1 if error. */
int mail_transaction_log_create(struct mail_transaction_log *log, bool reset);
/* Close all the open transactions log files. */
void mail_transaction_log_close(struct mail_transaction_log *log);

/* Notify of indexid change */
void mail_transaction_log_indexid_changed(struct mail_transaction_log *log);

/* Returns the file seq/offset where the mailbox is currently synced at.
   Since the log is rotated only when mailbox is fully synced, the sequence
   points always to the latest file. This function doesn't actually find the
   latest sync position, so you'll need to use eg. log_view_set() before
   calling this. */
void mail_transaction_log_get_mailbox_sync_pos(struct mail_transaction_log *log,
					       uint32_t *file_seq_r,
					       uoff_t *file_offset_r);
/* Set the current mailbox sync position. file_seq must always be the latest
   log file's sequence. The offset written automatically to the log when
   other transactions are being written. */
void mail_transaction_log_set_mailbox_sync_pos(struct mail_transaction_log *log,
					       uint32_t file_seq,
					       uoff_t file_offset);

struct mail_transaction_log_view *
mail_transaction_log_view_open(struct mail_transaction_log *log);
void mail_transaction_log_view_close(struct mail_transaction_log_view **view);

/* Set view boundaries. Returns 1 if ok, 0 if files are lost, corrupted or the
   offsets are broken, -1 if I/O error. reset_r=TRUE if the whole index should
   be reset before applying any changes. */
int mail_transaction_log_view_set(struct mail_transaction_log_view *view,
				  uint32_t min_file_seq, uoff_t min_file_offset,
				  uint32_t max_file_seq, uoff_t max_file_offset,
				  bool *reset_r, const char **reason_r);
/* Scan through all of the log files that we can find.
   Returns -1 if error, 0 if ok. */
int mail_transaction_log_view_set_all(struct mail_transaction_log_view *view);
/* Clear the view. If oldest_file_seq > 0, keep it and newer log files
   referenced so we don't get desynced. */
void mail_transaction_log_view_clear(struct mail_transaction_log_view *view,
				     uint32_t oldest_file_seq);

/* Read next transaction record from current position. The position is updated.
   Returns -1 if error, 0 if we're at end of the view, 1 if ok. */
int mail_transaction_log_view_next(struct mail_transaction_log_view *view,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r);
/* Mark the current view's position to the record returned previously with
   _log_view_next(). */
void mail_transaction_log_view_mark(struct mail_transaction_log_view *view);
/* Seek to previously marked position. */
void mail_transaction_log_view_rewind(struct mail_transaction_log_view *view);

/* Returns the position of the record returned previously with
   mail_transaction_log_view_next() */
void
mail_transaction_log_view_get_prev_pos(struct mail_transaction_log_view *view,
				       uint32_t *file_seq_r,
				       uoff_t *file_offset_r);
/* Return the modseq of the change returned previously with _view_next(). */
uint64_t
mail_transaction_log_view_get_prev_modseq(struct mail_transaction_log_view *view);
/* Returns TRUE if we're at the end of the view window. */
bool mail_transaction_log_view_is_last(struct mail_transaction_log_view *view);

/* Marks the log file in current position to be corrupted. */
void
mail_transaction_log_view_set_corrupted(struct mail_transaction_log_view *view,
					const char *fmt, ...)
	ATTR_FORMAT(2, 3) ATTR_COLD;
bool
mail_transaction_log_view_is_corrupted(struct mail_transaction_log_view *view);

int mail_transaction_log_append_begin(struct mail_index *index,
				      enum mail_transaction_type flags,
				      struct mail_transaction_log_append_ctx **ctx_r);
void mail_transaction_log_append_add(struct mail_transaction_log_append_ctx *ctx,
				     enum mail_transaction_type type,
				     const void *data, size_t size);
int mail_transaction_log_append_commit(struct mail_transaction_log_append_ctx **ctx);

/* Lock transaction log for index synchronization. This is used as the main
   exclusive lock for index changes. The index/log can still be read since they
   don't use locking, but the log can't be written to while it's locked.
   Returns 0 on success, -1 if locking failed for any reason.

   After successfully locking the transaction log, the log file is also fully
   mapped into memory and its sync_offset updated. The locked file's sequence
   and sync_offset are returned. */
int mail_transaction_log_sync_lock(struct mail_transaction_log *log,
				   const char *lock_reason,
				   uint32_t *file_seq_r, uoff_t *file_offset_r);
void mail_transaction_log_sync_unlock(struct mail_transaction_log *log,
				      const char *lock_reason);
/* Returns the current head. Works only when log is locked. */
void mail_transaction_log_get_head(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r);
/* Returns the current tail from which all files are open to head. */
void mail_transaction_log_get_tail(struct mail_transaction_log *log,
				   uint32_t *file_seq_r);
/* Returns TRUE if given seq/offset is current head log's rotate point. */
bool mail_transaction_log_is_head_prev(struct mail_transaction_log *log,
				       uint32_t file_seq, uoff_t file_offset);

/* Move currently opened log head file to memory (called by
   mail_index_move_to_memory()) */
int mail_transaction_log_move_to_memory(struct mail_transaction_log *log);
/* Unlink transaction log files */
int mail_transaction_log_unlink(struct mail_transaction_log *log);

#endif
