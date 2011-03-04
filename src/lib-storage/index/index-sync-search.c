/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "mail-search.h"
#include "mailbox-search-result-private.h"
#include "index-search-result.h"
#include "index-sync-private.h"

static bool
search_result_want_flag_updates(const struct mail_search_result *result)
{
	if (!result->args_have_flags && !result->args_have_keywords &&
	    !result->args_have_modseq) {
		/* search result doesn't care about flag changes */
		return FALSE;
	}
	return TRUE;
}

static void index_sync_uidify_array(struct index_mailbox_sync_context *ctx,
				    const ARRAY_TYPE(seq_range) *changes)
{
	const struct seq_range *range;
	uint32_t seq, uid;

	array_foreach(changes, range) {
		for (seq = range->seq1; seq <= range->seq2; seq++) {
			mail_index_lookup_uid(ctx->ctx.box->view, seq, &uid);
			seq_range_array_add(&ctx->all_flag_update_uids, 0, uid);
		}
	}
}

static void index_sync_uidify(struct index_mailbox_sync_context *ctx)
{
	unsigned int count;

	count = array_count(&ctx->flag_updates) +
		array_count(&ctx->hidden_updates);
	i_array_init(&ctx->all_flag_update_uids, count*2);

	index_sync_uidify_array(ctx, &ctx->flag_updates);
	index_sync_uidify_array(ctx, &ctx->hidden_updates);
}

void index_sync_search_results_uidify(struct index_mailbox_sync_context *ctx)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	i_assert(!array_is_created(&ctx->all_flag_update_uids));

	results = array_get(&ctx->ctx.box->search_results, &count);
	for (i = 0; i < count; i++) {
		if ((results[i]->flags & MAILBOX_SEARCH_RESULT_FLAG_UPDATE) != 0 &&
		    search_result_want_flag_updates(results[i])) {
			index_sync_uidify(ctx);
			break;
		}
	}
}

static void
search_result_update(struct index_mailbox_sync_context *ctx,
		     struct mail_search_result *result)
{
	if ((result->flags & MAILBOX_SEARCH_RESULT_FLAG_UPDATE) == 0) {
		/* not an updateable search result */
		return;
	}

	if (search_result_want_flag_updates(result)) {
		(void)index_search_result_update_flags(result,
						&ctx->all_flag_update_uids);
	}
	(void)index_search_result_update_appends(result, ctx->messages_count);
}

void index_sync_search_results_update(struct index_mailbox_sync_context *ctx)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	results = array_get(&ctx->ctx.box->search_results, &count);
	for (i = 0; i < count; i++)
		search_result_update(ctx, results[i]);
}

void index_sync_search_results_expunge(struct index_mailbox_sync_context *ctx)
{
	if (ctx->expunges != NULL) {
		index_search_results_update_expunges(ctx->ctx.box,
						     ctx->expunges);
	}
}
