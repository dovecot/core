#ifndef __MAIL_TRANSACTION_LOG_VIEW_H
#define __MAIL_TRANSACTION_LOG_VIEW_H

#include "file-dotlock.h"
#include "mail-transaction-log.h"

/* Rotate when log is older than ROTATE_TIME and larger than MIN_SIZE */
#define MAIL_TRANSACTION_LOG_ROTATE_MIN_SIZE (1024*32)
/* If log is larger than MAX_SIZE, rotate regardless of the time */
#define MAIL_TRANSACTION_LOG_ROTATE_MAX_SIZE (1024*1024)
#define MAIL_TRANSACTION_LOG_ROTATE_TIME (60*5)

#define MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file) ((file)->fd == -1)

struct mail_transaction_log_file {
	struct mail_transaction_log *log;
        struct mail_transaction_log_file *next;

	/* refcount=0 is a valid state. files start that way, and they're
	   freed only when mail_transaction_logs_clean() is called. */
	int refcount;

	char *filepath;
	int fd;

	ino_t st_ino;
	dev_t st_dev;
	time_t last_mtime;
	uoff_t last_size;

	struct mail_transaction_log_header hdr;
	buffer_t *buffer;
	uoff_t buffer_offset;
	void *mmap_base;
	size_t mmap_size;

	/* points to the next uncommitted transaction. usually same as EOF. */
	uoff_t sync_offset;
	/* saved_tail_offset is the offset that was last written to transaction
	   log. max_tail_offset is what should be written to the log the next
	   time a transaction is written. transaction log handling may update
	   max_tail_offset automatically by making it skip external transactions
	   after the last saved offset (to avoid re-reading them unneededly). */
	uoff_t saved_tail_offset, max_tail_offset;

	struct file_lock *file_lock;

	unsigned int locked:1;
};

struct mail_transaction_log {
	struct mail_index *index;
        struct mail_transaction_log_view *views;

	/* files is a linked list of all the opened log files. the list is
	   sorted by the log file sequence, so that transaction views can use
	   them easily. head contains a pointer to the newest log file. */
	struct mail_transaction_log_file *files, *head;
	/* open_file is used temporarily while opening the log file.
	   if _open() failed, it's left there for _create(). */
	struct mail_transaction_log_file *open_file;

	unsigned int dotlock_count;
        struct dotlock_settings dotlock_settings, new_dotlock_settings;
	struct dotlock *dotlock;
};

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
	__attr_format__(2, 3);

struct mail_transaction_log_file *
mail_transaction_log_file_alloc_in_memory(struct mail_transaction_log *log);
struct mail_transaction_log_file *
mail_transaction_log_file_alloc(struct mail_transaction_log *log,
				const char *path);
void mail_transaction_log_file_free(struct mail_transaction_log_file **file);

int mail_transaction_log_file_open(struct mail_transaction_log_file *file,
				   bool check_existing);
int mail_transaction_log_file_create(struct mail_transaction_log_file *file);
int mail_transaction_log_file_lock(struct mail_transaction_log_file *file);

int mail_transaction_log_find_file(struct mail_transaction_log *log,
				   uint32_t file_seq,
				   struct mail_transaction_log_file **file_r);

/* Returns 1 if ok, 0 if file is corrupted or offset range is invalid,
   -1 if I/O error */
int mail_transaction_log_file_map(struct mail_transaction_log_file *file,
				  uoff_t start_offset, uoff_t end_offset);
void mail_transaction_log_file_move_to_memory(struct mail_transaction_log_file
					      *file);

void mail_transaction_logs_clean(struct mail_transaction_log *log);

bool mail_transaction_log_want_rotate(struct mail_transaction_log *log);
int mail_transaction_log_rotate(struct mail_transaction_log *log);
int mail_transaction_log_lock_head(struct mail_transaction_log *log);
void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file);

#endif
