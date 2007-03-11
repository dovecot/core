#ifndef __MAIL_TRANSACTION_LOG_VIEW_H
#define __MAIL_TRANSACTION_LOG_VIEW_H

#include "file-dotlock.h"
#include "mail-transaction-log.h"

/* Rotate when log is older than ROTATE_TIME and larger than MIN_SIZE */
#define MAIL_TRANSACTION_LOG_ROTATE_MIN_SIZE (1024*128)
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

	buffer_t *buffer;
	uoff_t buffer_offset;
	void *mmap_base;
	size_t mmap_size;

	struct mail_transaction_log_header hdr;
	uoff_t sync_offset;
	uint32_t first_append_size;

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

	unsigned int dotlock_count;
        struct dotlock_settings dotlock_settings, new_dotlock_settings;
	struct dotlock *dotlock;
};

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
	__attr_format__(2, 3);

int mail_transaction_log_file_find(struct mail_transaction_log *log,
				   uint32_t file_seq,
				   struct mail_transaction_log_file **file_r);

int mail_transaction_log_file_map(struct mail_transaction_log_file *file,
				  uoff_t start_offset, uoff_t end_offset);

void mail_transaction_logs_clean(struct mail_transaction_log *log);

int mail_transaction_log_rotate(struct mail_transaction_log *log, bool lock);
int mail_transaction_log_lock_head(struct mail_transaction_log *log);
void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file);

#endif
