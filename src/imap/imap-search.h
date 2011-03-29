#ifndef IMAP_SEARCH_H
#define IMAP_SEARCH_H

#include <sys/time.h>

enum search_return_options {
	SEARCH_RETURN_ESEARCH		= 0x0001,
	SEARCH_RETURN_MIN		= 0x0002,
	SEARCH_RETURN_MAX		= 0x0004,
	SEARCH_RETURN_ALL		= 0x0008,
	SEARCH_RETURN_COUNT		= 0x0010,
	SEARCH_RETURN_MODSEQ		= 0x0020,
	SEARCH_RETURN_SAVE		= 0x0040,
	SEARCH_RETURN_UPDATE		= 0x0080,
	SEARCH_RETURN_PARTIAL		= 0x0100
/* Options that don't return any seq/uid results */
#define SEARCH_RETURN_NORESULTS \
	(SEARCH_RETURN_ESEARCH | SEARCH_RETURN_MODSEQ | SEARCH_RETURN_SAVE | \
	 SEARCH_RETURN_UPDATE)
};

struct imap_search_context {
	struct client_command_context *cmd;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
        struct mail_search_context *search_ctx;

	struct mail_search_args *sargs;
	enum search_return_options return_options;
	uint32_t partial1, partial2;

	struct timeout *to;
	ARRAY_TYPE(seq_range) result;
	unsigned int result_count;

	uint64_t highest_seen_modseq;
	struct timeval start_time;

	unsigned int have_seqsets:1;
	unsigned int have_modseqs:1;
	unsigned int sorting:1;
};

int cmd_search_parse_return_if_found(struct imap_search_context *ctx,
				     const struct imap_arg **args);

bool imap_search_start(struct imap_search_context *ctx,
		       struct mail_search_args *sargs,
		       const enum mail_sort_type *sort_program);

#endif
