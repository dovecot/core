#ifndef INDEX_SEARCH_PRIVATE_H
#define INDEX_SEARCH_PRIVATE_H

#include "mail-storage-private.h"

#include <sys/time.h>

struct mail_search_mime_part;
struct imap_message_part;

struct index_search_context {
        struct mail_search_context mail_ctx;
	struct mail_index_view *view;
	struct mailbox *box;

	uint32_t pvt_uid, pvt_seq;

	enum mail_fetch_field extra_wanted_fields;
	struct mailbox_header_lookup_ctx *extra_wanted_headers;

	uint32_t seq1, seq2;
	struct mail *cur_mail;
	struct index_mail *cur_imail;
	struct mail_thread_context *thread_ctx;

	struct timeval search_start_time, last_notify;
	struct timeval last_nonblock_timeval;
	unsigned long long cost, next_time_check_cost;

	bool failed:1;
	bool sorted:1;
	bool have_seqsets:1;
	bool have_index_args:1;
	bool have_mailbox_args:1;
};

struct mail *index_search_get_mail(struct index_search_context *ctx);

int index_search_mime_arg_match(struct mail_search_arg *args,
	struct index_search_context *ctx);
void index_search_mime_arg_deinit(struct mail_search_arg *arg,
	struct index_search_context *ctx);

#endif
