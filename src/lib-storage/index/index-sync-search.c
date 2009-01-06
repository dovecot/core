/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "mail-search.h"
#include "mailbox-search-result-private.h"
#include "index-search-result.h"
#include "index-sync-private.h"

static bool
search_result_merge_changes(struct index_mailbox_sync_context *ctx,
			    const struct mail_search_result *result)
{
	unsigned int count;

	if (!result->args_have_flags && !result->args_have_keywords &&
	    !result->args_have_modseq) {
		/* search result doesn't care about flag changes */
		return FALSE;
	}
	if (ctx->all_flag_updates != NULL) {
		/* already merged */
		return TRUE;
	}

	if (array_count(&ctx->hidden_updates) == 0) {
		ctx->all_flag_updates = &ctx->flag_updates;
		return TRUE;
	}
	if (array_count(&ctx->flag_updates) == 0) {
		ctx->all_flag_updates = &ctx->hidden_updates;
		return TRUE;
	}

	/* both hidden and non-hidden changes. merge them */
	count = array_count(&ctx->flag_updates) +
		array_count(&ctx->hidden_updates);

	ctx->all_flag_updates = &ctx->all_flag_updates_merge;
	i_array_init(ctx->all_flag_updates, count);
	seq_range_array_merge(ctx->all_flag_updates, &ctx->flag_updates);
	seq_range_array_merge(ctx->all_flag_updates, &ctx->hidden_updates);
	return TRUE;
}

static void
search_result_update(struct index_mailbox_sync_context *ctx,
		     struct mail_search_result *result)
{
	if ((result->flags & MAILBOX_SEARCH_RESULT_FLAG_UPDATE) == 0) {
		/* not an updateable search result */
		return;
	}

	if (search_result_merge_changes(ctx, result)) {
		(void)index_search_result_update_flags(result,
						       ctx->all_flag_updates);
	}
	(void)index_search_result_update_appends(result, ctx->messages_count);
}

void index_sync_search_results_update(struct index_mailbox_sync_context *ctx)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	results = array_get(&ctx->ibox->box.search_results, &count);
	for (i = 0; i < count; i++)
		search_result_update(ctx, results[i]);
}

void index_sync_search_results_expunge(struct index_mailbox_sync_context *ctx)
{
	if (ctx->expunges != NULL) {
		index_search_results_update_expunges(&ctx->ibox->box,
						     ctx->expunges);
	}
}
