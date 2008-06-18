#ifndef MAILBOX_SEARCH_RESULT_PRIVATE_H
#define MAILBOX_SEARCH_RESULT_PRIVATE_H

#include "mail-storage.h"

struct mail_search_result {
	struct mailbox *box;
	enum mailbox_search_result_flags flags;
	struct mail_search_args *search_args;

	/* UIDs of messages currently in the result */
	ARRAY_TYPE(seq_range) uids;
	/* UIDs of messages that will never match the result */
	ARRAY_TYPE(seq_range) never_uids;
	ARRAY_TYPE(seq_range) removed_uids, added_uids;

	unsigned int args_have_flags:1;
	unsigned int args_have_keywords:1;
	unsigned int args_have_modseq:1;
};

struct mail_search_result *
mailbox_search_result_alloc(struct mailbox *box, struct mail_search_args *args,
			    enum mailbox_search_result_flags flags);

/* called when initial search is done. */
void mailbox_search_result_initial_done(struct mail_search_result *result);
void mailbox_search_results_initial_done(struct mail_search_context *ctx);

void mailbox_search_result_add(struct mail_search_result *result, uint32_t uid);
void mailbox_search_result_remove(struct mail_search_result *result,
				  uint32_t uid);
void mailbox_search_results_add(struct mail_search_context *ctx, uint32_t uid);
void mailbox_search_results_remove(struct mailbox *box, uint32_t uid);

void mailbox_search_result_never(struct mail_search_result *result,
				 uint32_t uid);
void mailbox_search_results_never(struct mail_search_context *ctx,
				  uint32_t uid);

#endif
