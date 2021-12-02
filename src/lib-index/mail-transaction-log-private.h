#ifndef MAIL_TRANSACTION_LOG_VIEW_H
#define MAIL_TRANSACTION_LOG_VIEW_H

#include "buffer.h"
#include "mail-transaction-log.h"

struct dotlock_settings;

/* Synchronization can take a while sometimes, especially when copying lots of
   mails. */
#define MAIL_TRANSACTION_LOG_LOCK_TIMEOUT (3*60)
#define MAIL_TRANSACTION_LOG_DOTLOCK_CHANGE_TIMEOUT (3*60)

#define MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file) ((file)->fd == -1)

#define LOG_FILE_MODSEQ_CACHE_SIZE 10

struct modseq_cache {
	uoff_t offset;
	uint64_t highest_modseq;
};

struct mail_transaction_log_file {
	struct mail_transaction_log *log;
	/* Next file in the mail_transaction_log.files list. Sorted by
	   hdr.file_seq. */
	struct mail_transaction_log_file *next;

	/* refcount=0 is a valid state. files start that way, and they're
	   freed only when mail_transaction_logs_clean() is called. */
	int refcount;

	char *filepath;
	int fd;

	/* Cached values for last stat()/fstat() */
	ino_t st_ino;
	dev_t st_dev;
	time_t last_mtime;
	uoff_t last_size;

	/* Used to avoid logging mmap() errors too rapidly. */
	time_t last_mmap_error_time;
	/* If non-NULL, the log file should be rotated. The string contains a
	   human-readable reason why the rotation was requested. */
	char *need_rotate;

	/* Copy of the log file header. Set when opened. */
	struct mail_transaction_log_header hdr;
	/* Buffer that points to mmap_base */
	buffer_t mmap_buffer;
	/* Buffer that can be used to access the log file contents. Either
	   points to mmap_buffer, or it's a copy of the file contents starting
	   from buffer_offset. */
	buffer_t *buffer;
	/* Offset to log where the buffer starts from. 0 with mmaped log. */
	uoff_t buffer_offset;
	/* If non-NULL, mmap()ed log file */
	void *mmap_base;
	size_t mmap_size;

	/* Offset to log file how far it's been read. Usually it's the same
	   as the log file size. However, if the last multi-record transaction
	   wasn't fully written (or is in the middle of being written), this
	   points to the beginning of the MAIL_TRANSACTION_BOUNDARY record. */
	uoff_t sync_offset;
	/* highest modseq at sync_offset */
	uint64_t sync_highest_modseq;
	/* The last mail_index_header.log_file_tail_offset update that was
	   read from the log. */
	uoff_t last_read_hdr_tail_offset;
	/* Update mail_index_header.log_file_tail_offset to this offset the
	   next time a transaction is written. Transaction log handling may
	   increase this automatically by making it skip external transactions
	   after last_read_hdr_tail_offset (to avoid re-reading them
	   needlessly). */
	uoff_t max_tail_offset;

	/* Last seen offsets for MAIL_TRANSACTION_INDEX_DELETED and
	   MAIL_TRANSACTION_INDEX_UNDELETED records. These are used to update
	   mail_index.index_delete* fields. */
	uoff_t index_deleted_offset, index_undeleted_offset;

	/* Cache to optimize mail_transaction_log_file_get_modseq_next_offset()
	   so it doesn't always have to start from the beginning of the log
	   file to find the wanted modseq. */
	struct modseq_cache modseq_cache[LOG_FILE_MODSEQ_CACHE_SIZE];

	/* Lock for the log file fd. If dotlocking is used, this is NULL and
	   mail_transaction_log.dotlock is used instead. */
	struct file_lock *file_lock;
	/* Time when the log was successfully locked */
	time_t lock_create_time;

	/* Log is currently locked. */
	bool locked:1;
	/* TRUE if sync_offset has already been updated while this log was
	   locked. This can be used to optimize away unnecessary checks to see
	   whether there's more data written to log after sync_offset. */
	bool locked_sync_offset_updated:1;
	/* Log file has found to be corrupted. Stop trying to read it.
	   The indexid is also usually overwritten to be 0 in the log header at
	   this time. */
	bool corrupted:1;
};

struct mail_transaction_log {
	struct mail_index *index;
	/* Linked list of all transaction log views */
	struct mail_transaction_log_view *views;
	/* Paths to .log and .log.2 */
	char *filepath, *filepath2;

	/* Linked list of all the opened log files. The oldest files may have
	   already been unlinked. The list is sorted by the log file sequence
	   (oldest/lowest first), so that transaction views can use them
	   easily. */
	struct mail_transaction_log_file *files;
	/* Latest log file (the last file in the files linked list) */
	struct mail_transaction_log_file *head;
	/* open_file is used temporarily while opening the log file.
	   if mail_transaction_log_open() failed, it's left there for
	   mail_transaction_log_create(). */
	struct mail_transaction_log_file *open_file;

	/* Normally the .log locking is done via their file descriptors, so
	   e.g. rotating a log needs to lock both the old and the new files
	   at the same time. However, when FILE_LOCK_METHOD_DOTLOCK is used,
	   the lock isn't file-specific. There is just a single dotlock that
	   is created by the first log file lock. The second lock simply
	   increases the refcount. (It's not expected that there would be more
	   than 2 locks.) */
	int dotlock_refcount;
	struct dotlock *dotlock;

	/* This session has already checked whether an old .log.2 should be
	   unlinked. */
	bool log_2_unlink_checked:1;
};

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
	ATTR_FORMAT(2, 3) ATTR_COLD;

void mail_transaction_log_get_dotlock_set(struct mail_transaction_log *log,
					  struct dotlock_settings *set_r);

struct mail_transaction_log_file *
mail_transaction_log_file_alloc_in_memory(struct mail_transaction_log *log);
struct mail_transaction_log_file *
mail_transaction_log_file_alloc(struct mail_transaction_log *log,
				const char *path);
void mail_transaction_log_file_free(struct mail_transaction_log_file **file);

/* Returns 1 if log was opened, 0 if it didn't exist or was already open,
   -1 if error. */
int mail_transaction_log_file_open(struct mail_transaction_log_file *file,
				   const char **reason_r);
int mail_transaction_log_file_create(struct mail_transaction_log_file *file,
				     bool reset);
int mail_transaction_log_file_lock(struct mail_transaction_log_file *file);

int mail_transaction_log_find_file(struct mail_transaction_log *log,
				   uint32_t file_seq, bool nfs_flush,
				   struct mail_transaction_log_file **file_r,
				   const char **reason_r);

/* Returns 1 if ok, 0 if file is corrupted or offset range is invalid,
   -1 if I/O error */
int mail_transaction_log_file_map(struct mail_transaction_log_file *file,
				  uoff_t start_offset, uoff_t end_offset,
				  const char **reason_r);
int mail_transaction_log_file_move_to_memory(struct mail_transaction_log_file *file);

void mail_transaction_logs_clean(struct mail_transaction_log *log);

bool mail_transaction_log_want_rotate(struct mail_transaction_log *log,
				      const char **reason_r);
int mail_transaction_log_rotate(struct mail_transaction_log *log, bool reset);
int mail_transaction_log_lock_head(struct mail_transaction_log *log,
				   const char *lock_reason);
void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file,
				      const char *lock_reason);

void mail_transaction_update_modseq(const struct mail_transaction_header *hdr,
				    const void *data, uint64_t *cur_modseq,
				    unsigned int version);
/* Returns 1 if ok, 0 if file is corrupted or offset range is invalid,
   -1 if I/O error */
int mail_transaction_log_file_get_highest_modseq_at(
		struct mail_transaction_log_file *file,
		uoff_t offset, uint64_t *highest_modseq_r,
		const char **error_r);
int mail_transaction_log_file_get_modseq_next_offset(
		struct mail_transaction_log_file *file,
		uint64_t modseq, uoff_t *next_offset_r);

#endif
