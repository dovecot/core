/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "mail-search.h"
#include "mailbox-search-result-private.h"
#include "index-sync-private.h"

static void
search_result_range_remove(struct mail_search_result *result,
			   const ARRAY_TYPE(seq_range) *search_seqs_range,
			   unsigned int *pos,
			   uint32_t *next_seq, uint32_t last_seq)
{
	struct index_mailbox *ibox = (struct index_mailbox *)result->box;
	const struct seq_range *seqs;
	unsigned int i, count;
	uint32_t seq, uid;

	seq = *next_seq;
	seqs = array_get(search_seqs_range, &count);
	for (i = *pos; seqs[i].seq2 < last_seq;) {
		i_assert(seqs[i].seq1 <= seq);
		for (; seq <= seqs[i].seq2; seq++) {
			mail_index_lookup_uid(ibox->view, seq, &uid);
			mailbox_search_result_remove(result, uid);
		}
		i++;
		i_assert(i < count);
		seq = seqs[i].seq1;
	}

	i_assert(seqs[i].seq1 <= seq && seqs[i].seq2 >= last_seq);
	for (; seq <= last_seq; seq++) {
		mail_index_lookup_uid(ibox->view, seq, &uid);
		mailbox_search_result_remove(result, uid);
	}
	if (seq > seqs[i].seq2) {
		/* finished this range */
		if (++i < count)
			seq = seqs[i].seq1;
		else {
			/* this was the last searched message */
			seq = 0;
		}
	}

	*next_seq = seq;
	*pos = i;
}

static int
search_result_update_search(struct mail_search_result *result,
			    const ARRAY_TYPE(seq_range) *search_seqs_range)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	const struct seq_range *search_seqs;
	unsigned int seqcount, seqpos;
	uint32_t next_seq;
	int ret;

	search_seqs = array_get(search_seqs_range, &seqcount);
	i_assert(seqcount > 0);
	next_seq = search_seqs[0].seq1;
	seqpos = 0;

	t = mailbox_transaction_begin(result->box, 0);
	search_ctx = mailbox_search_init(t, result->search_args, NULL);
	/* tell search that we're updating an existing search result,
	   so it can do some optimizations based on it */
	search_ctx->update_result = result;

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail) > 0) {
		i_assert(next_seq != 0);

		if (next_seq != mail->seq) {
			/* some messages in search_seqs didn't match.
			   make sure they don't exist in the search result. */
			search_result_range_remove(result, search_seqs_range,
						   &seqpos, &next_seq,
						   mail->seq-1);
			i_assert(next_seq == mail->seq);
		}
		if (search_seqs[seqpos].seq2 > next_seq) {
			next_seq++;
		} else if (++seqpos < seqcount) {
			next_seq = search_seqs[seqpos].seq1;
		} else {
			/* this was the last searched message */
			next_seq = 0;
		}
		/* match - make sure it exists in search result */
		mailbox_search_result_add(result, mail->uid);
	}
	mail_free(&mail);
	ret = mailbox_search_deinit(&search_ctx);

	if (next_seq != 0 && ret == 0) {
		/* last message(s) didn't match. make sure they don't exist
		   in the search result. */
		search_result_range_remove(result, search_seqs_range, &seqpos,
					   &next_seq,
					   search_seqs[seqcount-1].seq2);
	}

	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	return ret;
}

static int
search_result_update_existing(struct index_mailbox_sync_context *ctx,
			      struct mail_search_result *result)
{
	/* @UNSAFE */
	const ARRAY_TYPE(seq_range) *merge_ranges[2];
	ARRAY_TYPE(seq_range) changes;
	struct mail_search_arg search_arg;
	unsigned int i, count, merge_count = 0;
	int ret;

	/* get the changes we're interested in */
	if ((result->args_have_flags || result->args_have_keywords) &&
	    array_is_created(&ctx->flag_updates))
		merge_ranges[merge_count++] = &ctx->flag_updates;
	if (result->args_have_modseq && array_is_created(&ctx->modseq_updates))
		merge_ranges[merge_count++] = &ctx->modseq_updates;
	i_assert(merge_count < N_ELEMENTS(merge_ranges));

	for (i = 0, count = 0; i < merge_count; i++)
		count += array_count(merge_ranges[i]);
	if (count == 0) {
		/* no changes */
		return 0;
	}

	/* merge the changed sequences */
	t_array_init(&changes, count);
	for (i = 0; i < merge_count; i++)
		seq_range_array_merge(&changes, merge_ranges[i]);

	/* add a temporary search parameter to limit the search only to
	   the changed messages */
	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_SEQSET;
	search_arg.value.seqset = changes;
	search_arg.next = result->search_args->args;
	result->search_args->args = &search_arg;
	ret = search_result_update_search(result, &changes);
	i_assert(result->search_args->args == &search_arg);
	result->search_args->args = search_arg.next;
	return ret;
}

static int
search_result_update_appends(struct index_mailbox_sync_context *ctx,
			     struct mail_search_result *result)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct mail_search_arg search_arg;
	uint32_t message_count;
	int ret;

	message_count = mail_index_view_get_messages_count(ctx->ibox->view);
	if (ctx->messages_count == message_count) {
		/* no new messages */
		return 0;
	}

	/* add a temporary search parameter to limit the search only to
	   the new messages */
	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_SEQSET;
	t_array_init(&search_arg.value.seqset, 1);
	seq_range_array_add_range(&search_arg.value.seqset,
				  ctx->messages_count + 1, message_count);
	search_arg.next = result->search_args->args;
	result->search_args->args = &search_arg;

	/* add all messages matching the search to search result */
	t = mailbox_transaction_begin(result->box, 0);
	search_ctx = mailbox_search_init(t, result->search_args, NULL);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail) > 0)
		mailbox_search_result_add(result, mail->uid);
	mail_free(&mail);

	ret = mailbox_search_deinit(&search_ctx);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;

	i_assert(result->search_args->args == &search_arg);
	result->search_args->args = search_arg.next;
	return ret;
}

static void
search_result_update(struct index_mailbox_sync_context *ctx,
		     struct mail_search_result *result)
{
	if ((result->flags & MAILBOX_SEARCH_RESULT_FLAG_UPDATE) == 0)
		return;

	T_BEGIN {
		(void)search_result_update_existing(ctx, result);
	} T_END;
	(void)search_result_update_appends(ctx, result);
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
	struct mailbox *box = &ctx->ibox->box;
	const struct seq_range *seqs;
	unsigned int i, count;
	uint32_t seq, uid;

	if (ctx->expunges == NULL || array_count(&box->search_results) == 0)
		return;

	seqs = array_get(ctx->expunges, &count);
	for (i = 0; i < count; i++) {
		for (seq = seqs[i].seq1; seq <= seqs[i].seq2; seq++) {
			mail_index_lookup_uid(ctx->ibox->view, seq, &uid);
			mailbox_search_results_remove(box, uid);
		}
	}
}
