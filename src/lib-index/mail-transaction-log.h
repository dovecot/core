#ifndef __MAIL_TRANSACTION_LOG_H
#define __MAIL_TRANSACTION_LOG_H

#define MAIL_TRANSACTION_LOG_PREFIX ".log"
#define MAIL_TRANSACTION_LOG_ROTATE_SIZE (1024*128)
#define MAIL_TRANSACTION_LOG_ROTATE_MIN_TIME (60*5)

struct mail_transaction_log_header {
	uint32_t indexid;
	uint32_t file_seq;
	uint32_t prev_file_seq;
	uint32_t prev_file_offset;
};

enum mail_transaction_type {
	MAIL_TRANSACTION_EXPUNGE		= 0x00000001,
	MAIL_TRANSACTION_APPEND			= 0x00000002,
	MAIL_TRANSACTION_FLAG_UPDATE		= 0x00000004,
	MAIL_TRANSACTION_CACHE_RESET		= 0x00000008,
	MAIL_TRANSACTION_CACHE_UPDATE		= 0x00000010,
	MAIL_TRANSACTION_HEADER_UPDATE		= 0x00000020,
	MAIL_TRANSACTION_EXTRA_INTRO		= 0x00000040,
	MAIL_TRANSACTION_EXTRA_RESET		= 0x00000080,
	MAIL_TRANSACTION_EXTRA_HDR_UPDATE	= 0x00000100,
	MAIL_TRANSACTION_EXTRA_REC_UPDATE	= 0x00000200,

	MAIL_TRANSACTION_TYPE_MASK		= 0x0000ffff,

	/* since we'll expunge mails based on data read from transaction log,
	   try to avoid the possibility of corrupted transaction log expunging
	   messages. this value is ORed to the actual MAIL_TRANSACTION_EXPUNGE
	   flag. if it's not present, assume corrupted log. */
	MAIL_TRANSACTION_EXPUNGE_PROT		= 0x0000cd90,

	/* Mailbox synchronization noticed this change. */
	MAIL_TRANSACTION_EXTERNAL		= 0x10000000
};

struct mail_transaction_header {
	uint32_t size;
	uint32_t type; /* enum mail_transaction_type */
};

struct mail_transaction_expunge {
	uint32_t uid1, uid2;
};

struct mail_transaction_flag_update {
	uint32_t uid1, uid2;
	uint8_t add_flags;
	keywords_mask_t add_keywords;
	uint8_t remove_flags;
	keywords_mask_t remove_keywords;
};

struct mail_transaction_cache_reset {
	uint32_t new_file_seq;
};

struct mail_transaction_cache_update {
	uint32_t uid;
	uint32_t cache_offset;
};

struct mail_transaction_header_update {
	uint16_t offset;
	uint16_t size;
	/* unsigned char data[]; */
};

struct mail_transaction_extra_intro {
	uint32_t data_id; /* must be first */
	uint32_t hdr_size;
	uint16_t record_size;
	uint16_t name_size;
	/* unsigned char name[]; */
};

struct mail_transaction_extra_hdr_update {
	uint32_t data_id; /* must be first */
	uint16_t offset;
	uint16_t size;
	/* unsigned char data[]; */
};

struct mail_transaction_extra_rec_header {
	uint32_t data_id; /* must be first */
};

struct mail_transaction_extra_rec_update {
	uint32_t uid;
	/* unsigned char data[]; */
};

struct mail_transaction_log *
mail_transaction_log_open_or_create(struct mail_index *index);
void mail_transaction_log_close(struct mail_transaction_log *log);

struct mail_transaction_log_view *
mail_transaction_log_view_open(struct mail_transaction_log *log);
void mail_transaction_log_view_close(struct mail_transaction_log_view *view);

/* Set view boundaries. Returns -1 if error, 0 if ok. */
int
mail_transaction_log_view_set(struct mail_transaction_log_view *view,
			      uint32_t min_file_seq, uoff_t min_file_offset,
			      uint32_t max_file_seq, uoff_t max_file_offset,
			      enum mail_transaction_type type_mask);

/* Read next transaction record from current position. The position is updated.
   Returns -1 if error, 0 if we're at end of the view, 1 if ok. */
int mail_transaction_log_view_next(struct mail_transaction_log_view *view,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r, int *skipped_r);

/* Returns the position of the record returned previously with
   mail_transaction_log_view_next() */
void
mail_transaction_log_view_get_prev_pos(struct mail_transaction_log_view *view,
				       uint32_t *file_seq_r,
				       uoff_t *file_offset_r);

/* Marks the log file in current position to be corrupted. */
void
mail_transaction_log_view_set_corrupted(struct mail_transaction_log_view *view,
					const char *fmt, ...)
	__attr_format__(2, 3);
int
mail_transaction_log_view_is_corrupted(struct mail_transaction_log_view *view);

void mail_transaction_log_views_close(struct mail_transaction_log *log);

/* Write data to transaction log. This is atomic operation. Sequences in
   updates[] and expunges[] are relative to given view, they're modified
   to real ones. If nothing is written, log_file_seq_r and log_file_offset_r
   will be set to 0. */
int mail_transaction_log_append(struct mail_index_transaction *t,
				uint32_t *log_file_seq_r,
				uoff_t *log_file_offset_r);

/* Lock transaction log for index synchronization. Log cannot be read or
   written to while it's locked. Returns end offset. */
int mail_transaction_log_sync_lock(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r);
void mail_transaction_log_sync_unlock(struct mail_transaction_log *log);
/* Returns the current head. Works only when log is locked. */
void mail_transaction_log_get_head(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r);

#endif
