#ifndef INDEX_SEARCH_PRIVATE_H
#define INDEX_SEARCH_PRIVATE_H

#include "mail-storage-private.h"

struct index_search_context {
        struct mail_search_context mail_ctx;
	struct mail_index_view *view;
	struct mailbox *box;

	enum mail_fetch_field extra_wanted_fields;
	struct mailbox_header_lookup_ctx *extra_wanted_headers;

	uint32_t seq1, seq2;
	struct mail *mail;
	struct index_mail *imail;
	struct mail_thread_context *thread_ctx;

	struct timeval search_start_time, last_notify;
	struct timeval last_nonblock_timeval;
	unsigned long long cost, next_time_check_cost;

	unsigned int failed:1;
	unsigned int sorted:1;
	unsigned int have_seqsets:1;
	unsigned int have_index_args:1;
	unsigned int have_mailbox_args:1;
	unsigned int recheck_index_args:1;
};

void index_storage_search_init_context(struct index_search_context *ctx,
				       struct mailbox_transaction_context *t,
				       struct mail_search_args *args,
				       const enum mail_sort_type *sort_program,
				       enum mail_fetch_field wanted_fields,
				       struct mailbox_header_lookup_ctx *wanted_headers);

#endif
