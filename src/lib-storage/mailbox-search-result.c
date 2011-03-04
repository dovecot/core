/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "mail-search.h"
#include "mailbox-search-result-private.h"

static void
mailbox_search_result_analyze_args(struct mail_search_result *result,
				   struct mail_search_arg *arg)
{
	for (; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
			mailbox_search_result_analyze_args(result,
							   arg->value.subargs);
			break;
		case SEARCH_FLAGS:
			result->args_have_flags = TRUE;
			break;
		case SEARCH_KEYWORDS:
			result->args_have_keywords = TRUE;
			break;
		case SEARCH_MODSEQ:
			result->args_have_modseq = TRUE;
			break;
		default:
			break;
		}
	}
}

struct mail_search_result *
mailbox_search_result_alloc(struct mailbox *box, struct mail_search_args *args,
			    enum mailbox_search_result_flags flags)
{
	struct mail_search_result *result;

	result = i_new(struct mail_search_result, 1);
	result->box = box;
	result->flags = flags;
	i_array_init(&result->uids, 32);
	i_array_init(&result->never_uids, 128);

	if ((result->flags & MAILBOX_SEARCH_RESULT_FLAG_UPDATE) != 0) {
		result->search_args = args;
		mail_search_args_ref(result->search_args);
		mailbox_search_result_analyze_args(result, args->args);
	}

	array_append(&result->box->search_results, &result, 1);
	return result;
}

void mailbox_search_result_free(struct mail_search_result **_result)
{
	struct mail_search_result *result = *_result;
	struct mail_search_result *const *results;
	unsigned int i, count;

	*_result = NULL;

	results = array_get(&result->box->search_results, &count);
	for (i = 0; i < count; i++) {
		if (results[i] == result) {
			array_delete(&result->box->search_results, i, 1);
			break;
		}
	}
	i_assert(i != count);

	if (result->search_args != NULL)
		mail_search_args_unref(&result->search_args);

	array_free(&result->uids);
	array_free(&result->never_uids);
	if (array_is_created(&result->removed_uids)) {
		array_free(&result->removed_uids);
		array_free(&result->added_uids);
	}
	i_free(result);
}

struct mail_search_result *
mailbox_search_result_save(struct mail_search_context *ctx,
			   enum mailbox_search_result_flags flags)
{
	struct mail_search_result *result;

	result = mailbox_search_result_alloc(ctx->transaction->box,
					     ctx->args, flags);
	array_append(&ctx->results, &result, 1);
	return result;
}

void mailbox_search_result_initial_done(struct mail_search_result *result)
{
	if ((result->flags & MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC) != 0) {
		i_array_init(&result->removed_uids, 32);
		i_array_init(&result->added_uids, 32);
	}
	mail_search_args_seq2uid(result->search_args);
}

void mailbox_search_results_initial_done(struct mail_search_context *ctx)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	results = array_get(&ctx->results, &count);
	for (i = 0; i < count; i++)
		mailbox_search_result_initial_done(results[i]);
}

void mailbox_search_result_add(struct mail_search_result *result, uint32_t uid)
{
	i_assert(uid > 0);

	if (seq_range_exists(&result->uids, uid))
		return;

	seq_range_array_add(&result->uids, 0, uid);
	if (array_is_created(&result->added_uids)) {
		seq_range_array_add(&result->added_uids, 0, uid);
		seq_range_array_remove(&result->removed_uids, uid);
	}
}

void mailbox_search_result_remove(struct mail_search_result *result,
				  uint32_t uid)
{
	if (seq_range_array_remove(&result->uids, uid)) {
		if (array_is_created(&result->removed_uids)) {
			seq_range_array_add(&result->removed_uids, 0, uid);
			seq_range_array_remove(&result->added_uids, uid);
		}
	}
}

void mailbox_search_results_add(struct mail_search_context *ctx, uint32_t uid)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	results = array_get(&ctx->results, &count);
	for (i = 0; i < count; i++)
		mailbox_search_result_add(results[i], uid);
}

void mailbox_search_results_remove(struct mailbox *box, uint32_t uid)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	results = array_get(&box->search_results, &count);
	for (i = 0; i < count; i++)
		mailbox_search_result_remove(results[i], uid);
}

void mailbox_search_result_never(struct mail_search_result *result,
				 uint32_t uid)
{
	seq_range_array_add(&result->never_uids, 0, uid);
}

void mailbox_search_results_never(struct mail_search_context *ctx,
				  uint32_t uid)
{
	struct mail_search_result *const *results;
	unsigned int i, count;

	if (ctx->update_result != NULL)
		mailbox_search_result_never(ctx->update_result, uid);

	results = array_get(&ctx->results, &count);
	for (i = 0; i < count; i++)
		mailbox_search_result_never(results[i], uid);
}

const ARRAY_TYPE(seq_range) *
mailbox_search_result_get(struct mail_search_result *result)
{
	return &result->uids;
}

void mailbox_search_result_sync(struct mail_search_result *result,
				ARRAY_TYPE(seq_range) *removed_uids,
				ARRAY_TYPE(seq_range) *added_uids)
{
	array_clear(removed_uids);
	array_clear(added_uids);

	array_append_array(removed_uids, &result->removed_uids);
	array_append_array(added_uids, &result->added_uids);

	array_clear(&result->removed_uids);
	array_clear(&result->added_uids);
}
