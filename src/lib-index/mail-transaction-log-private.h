#ifndef __MAIL_TRANSACTION_LOG_VIEW_H
#define __MAIL_TRANSACTION_LOG_VIEW_H

#include "file-dotlock.h"
#include "mail-transaction-log.h"

#define MAIL_TRANSACTION_LOG_ROTATE_SIZE (1024*128)
#define MAIL_TRANSACTION_LOG_ROTATE_TIME (60*5)

#define MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file) ((file)->fd == -1)

struct mail_transaction_log_file {
	struct mail_transaction_log *log;
        struct mail_transaction_log_file *next;

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

	unsigned int locked:1;
};

struct mail_transaction_log {
	struct mail_index *index;
        struct mail_transaction_log_view *views;
	struct mail_transaction_log_file *head, *tail;

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

int mail_transaction_log_rotate(struct mail_transaction_log *log, int lock);
int mail_transaction_log_lock_head(struct mail_transaction_log *log);
void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file);

#endif
