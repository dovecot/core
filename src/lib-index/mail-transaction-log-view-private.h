#ifndef MAIL_TRANSACTION_LOG_VIEW_PRIVATE_H
#define MAIL_TRANSACTION_LOG_VIEW_PRIVATE_H

#include "mail-transaction-log-private.h"

struct mail_transaction_log_view {
	struct mail_transaction_log *log;
        struct mail_transaction_log_view *next;

	uint32_t min_file_seq, max_file_seq;
	uoff_t min_file_offset, max_file_offset;

	struct mail_transaction_header tmp_hdr;

	/* a list of log files we've referenced. we have to keep this list
	   explicitly because more files may be added into the linked list
	   at any time. */
	ARRAY_DEFINE(file_refs, struct mail_transaction_log_file *);
        struct mail_transaction_log_file *cur, *head, *tail;
	uoff_t cur_offset;

	uint64_t prev_modseq;
	uint32_t prev_file_seq;
	uoff_t prev_file_offset;

	struct mail_transaction_log_file *mark_file;
	uoff_t mark_offset, mark_next_offset;
	uint64_t mark_modseq;

	unsigned int broken:1;
};

#endif
