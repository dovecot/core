#ifndef MAIL_TRANSACTION_LOG_H
#define MAIL_TRANSACTION_LOG_H

#include "mail-index.h"

#define MAIL_TRANSACTION_LOG_SUFFIX ".log"

#define MAIL_TRANSACTION_LOG_MAJOR_VERSION 1
#define MAIL_TRANSACTION_LOG_MINOR_VERSION 2
#define MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE 24

struct mail_transaction_log_header {
	uint8_t major_version;
	uint8_t minor_version;
	uint16_t hdr_size;

	uint32_t indexid;
	uint32_t file_seq;
	uint32_t prev_file_seq;
	uint32_t prev_file_offset;
	uint32_t create_stamp;
	uint64_t initial_modseq; /* v1.1+ (note: log's major/minor version) */

	uint8_t compat_flags; /* enum mail_index_header_compat_flags, v1.2+ */
	uint8_t unused[3];
	uint32_t unused2; /* so that this struct is 64bit aligned */
};

enum mail_transaction_type {
	MAIL_TRANSACTION_EXPUNGE		= 0x00000001,
	MAIL_TRANSACTION_APPEND			= 0x00000002,
	MAIL_TRANSACTION_FLAG_UPDATE		= 0x00000004,
	MAIL_TRANSACTION_HEADER_UPDATE		= 0x00000020,
	MAIL_TRANSACTION_EXT_INTRO		= 0x00000040,
	MAIL_TRANSACTION_EXT_RESET		= 0x00000080,
	MAIL_TRANSACTION_EXT_HDR_UPDATE		= 0x00000100,
	MAIL_TRANSACTION_EXT_REC_UPDATE		= 0x00000200,
	MAIL_TRANSACTION_KEYWORD_UPDATE		= 0x00000400,
	MAIL_TRANSACTION_KEYWORD_RESET		= 0x00000800,
	MAIL_TRANSACTION_EXT_ATOMIC_INC		= 0x00001000,
	MAIL_TRANSACTION_EXPUNGE_GUID		= 0x00002000,
	MAIL_TRANSACTION_MODSEQ_UPDATE		= 0x00008000,
	MAIL_TRANSACTION_EXT_HDR_UPDATE32	= 0x00010000,
	MAIL_TRANSACTION_INDEX_DELETED		= 0x00020000,
	MAIL_TRANSACTION_INDEX_UNDELETED	= 0x00040000,
	MAIL_TRANSACTION_BOUNDARY		= 0x00080000,

	MAIL_TRANSACTION_TYPE_MASK		= 0x000fffff,

#define MAIL_TRANSACTION_EXT_MASK \
	(MAIL_TRANSACTION_EXT_INTRO | MAIL_TRANSACTION_EXT_RESET | \
	MAIL_TRANSACTION_EXT_HDR_UPDATE | MAIL_TRANSACTION_EXT_HDR_UPDATE32 | \
	MAIL_TRANSACTION_EXT_REC_UPDATE | MAIL_TRANSACTION_EXT_ATOMIC_INC)

	/* since we'll expunge mails based on data read from transaction log,
	   try to avoid the possibility of corrupted transaction log expunging
	   messages. this value is ORed to the actual MAIL_TRANSACTION_EXPUNGE*
	   flag. if it's not present, assume corrupted log. */
	MAIL_TRANSACTION_EXPUNGE_PROT		= 0x0000cd90,

	/* Mailbox synchronization noticed this change. */
	MAIL_TRANSACTION_EXTERNAL		= 0x10000000
};

struct mail_transaction_header {
	uint32_t size;
	uint32_t type; /* enum mail_transaction_type */
};

struct mail_transaction_modseq_update {
	uint32_t uid;
	/* don't use uint64_t here. it adds extra 32 bits of paddiong and also
	   causes problems with CPUs that require alignment */
	uint32_t modseq_low32;
	uint32_t modseq_high32;
};

struct mail_transaction_expunge {
	uint32_t uid1, uid2;
};
struct mail_transaction_expunge_guid {
	uint32_t uid;
	uint8_t guid_128[MAIL_GUID_128_SIZE];
};

struct mail_transaction_flag_update {
	uint32_t uid1, uid2;
	uint8_t add_flags;
	uint8_t remove_flags;
	uint16_t padding;
};

struct mail_transaction_keyword_update {
	uint8_t modify_type; /* enum modify_type : MODIFY_ADD / MODIFY_REMOVE */
	uint8_t padding;
	uint16_t name_size;
	/* unsigned char name[];
	   array of { uint32_t uid1, uid2; }
	*/
};

struct mail_transaction_keyword_reset {
	uint32_t uid1, uid2;
};

struct mail_transaction_header_update {
	uint16_t offset;
	uint16_t size;
	/* unsigned char data[]; */
};

enum {
	/* Don't shrink hdr_size, record_size or record_align but grow them
	   if necessary. */
	MAIL_TRANSACTION_EXT_INTRO_FLAG_NO_SHRINK = 0x01
};

struct mail_transaction_ext_intro {
	/* old extension: set ext_id. don't set name.
	   new extension: ext_id = (uint32_t)-1. give name. */
	uint32_t ext_id;
	uint32_t reset_id;
	uint32_t hdr_size;
	uint16_t record_size;
	uint16_t record_align;
	uint16_t flags;
	uint16_t name_size;
	/* unsigned char name[]; */
};

struct mail_transaction_ext_reset {
	uint32_t new_reset_id;
	uint8_t preserve_data;
	uint8_t unused_padding[3];
};

/* these are set for the last ext_intro */
struct mail_transaction_ext_hdr_update {
	uint16_t offset;
	uint16_t size;
	/* unsigned char data[]; */
};
/* this _update32 version should have been the only ext_hdr_update,
   but since 16bit integers were originally used for now we'll just use this
   only when actually needed to be backwards compatible. */
struct mail_transaction_ext_hdr_update32 {
	uint32_t offset;
	uint32_t size;
	/* unsigned char data[]; */
};

struct mail_transaction_ext_rec_update {
	uint32_t uid;
	/* unsigned char data[]; */
};
struct mail_transaction_ext_atomic_inc {
	uint32_t uid;
	int32_t diff;
};

struct mail_transaction_boundary {
	uint32_t size;
};

struct mail_transaction_log_append_ctx {
	struct mail_transaction_log *log;
	buffer_t *output;

	uint64_t new_highest_modseq;
	unsigned int external:1;
	unsigned int append_sync_offset:1;
	unsigned int sync_includes_this:1;
	unsigned int want_fsync:1;
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

/* Set view boundaries. Returns -1 if error, 0 if files are lost, 1 if ok.
   reset_r=TRUE if the whole index should be reset before applying any
   changes. */
int mail_transaction_log_view_set(struct mail_transaction_log_view *view,
				  uint32_t min_file_seq, uoff_t min_file_offset,
				  uint32_t max_file_seq, uoff_t max_file_offset,
				  bool *reset_r);
/* Clear the view. Keep oldest_file_seq and newer log files referenced so we
   don't get desynced. */
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
	ATTR_FORMAT(2, 3);
bool
mail_transaction_log_view_is_corrupted(struct mail_transaction_log_view *view);

void mail_transaction_log_views_close(struct mail_transaction_log *log);

int mail_transaction_log_append_begin(struct mail_index *index, bool external,
				      struct mail_transaction_log_append_ctx **ctx_r);
void mail_transaction_log_append_add(struct mail_transaction_log_append_ctx *ctx,
				     enum mail_transaction_type type,
				     const void *data, size_t size);
int mail_transaction_log_append_commit(struct mail_transaction_log_append_ctx **ctx);

/* Lock transaction log for index synchronization. Log cannot be read or
   written to while it's locked. Returns end offset. */
int mail_transaction_log_sync_lock(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r);
void mail_transaction_log_sync_unlock(struct mail_transaction_log *log);
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
void mail_transaction_log_move_to_memory(struct mail_transaction_log *log);
/* Returns mtime of the transaction log head file.
   If it doesn't exist, mtime_r is set to 0. */
int mail_transaction_log_get_mtime(struct mail_transaction_log *log,
				   time_t *mtime_r);

#endif
