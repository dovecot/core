#ifndef __MAIL_TRANSACTION_LOG_VIEW_H
#define __MAIL_TRANSACTION_LOG_VIEW_H

#include "file-dotlock.h"
#include "mail-transaction-log.h"

struct mail_transaction_log_file {
	struct mail_transaction_log *log;
        struct mail_transaction_log_file *next;

	int refcount;

	char *filepath;
	int fd;
	int lock_type;

	ino_t st_ino;
	dev_t st_dev;
	time_t last_mtime;

	buffer_t *buffer;
	uoff_t buffer_offset;
	void *mmap_base;
	size_t mmap_size;

	struct mail_transaction_log_header hdr;
};

struct mail_transaction_log {
	struct mail_index *index;
        struct mail_transaction_log_view *views;
	struct mail_transaction_log_file *head, *tail;

	unsigned int dotlock_count;
	struct dotlock dotlock;
};

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...);

int mail_transaction_log_file_find(struct mail_transaction_log *log,
				   uint32_t file_seq,
				   struct mail_transaction_log_file **file_r);

int mail_transaction_log_file_map(struct mail_transaction_log_file *file,
				  uoff_t start_offset, uoff_t end_offset);

void mail_transaction_logs_clean(struct mail_transaction_log *log);

#endif
