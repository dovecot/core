/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "mail-search.h"
#include "mailbox-search-result-private.h"
#include "index-storage.h"
#include "index-search-result.h"

static void
search_result_range_remove(struct mail_search_result *result,
			   const ARRAY_TYPE(seq_range) *changed_uids_arr,
			   unsigned int *idx,
			   uint32_t *next_uid, uint32_t last_uid)
{
	const struct seq_range *uids;
	unsigned int i, count;
	uint32_t uid;

	/* remove full seq_ranges */
	uid = *next_uid;
	uids = array_get(changed_uids_arr, &count);
	for (i = *idx; uids[i].seq2 < last_uid;) {
		i_assert(uids[i].seq1 <= uid);
		for (; uid <= uids[i].seq2; uid++)
			mailbox_search_result_remove(result, uid);
		i++;
		i_assert(i < count);
		uid = uids[i].seq1;
	}

	/* remove the last seq_range */
	i_assert(uids[i].seq1 <= uid && uids[i].seq2 >= last_uid);
	for (; uid <= last_uid; uid++)
		mailbox_search_result_remove(result, uid);

	if (uid > uids[i].seq2) {
		/* finished this range */
		if (++i < count)
			uid = uids[i].seq1;
		else {
			/* this was the last searched message */
			uid = 0;
		}
	}

	*next_uid = uid;
	*idx = i;
}

static int
search_result_update_search(struct mail_search_result *result,
			    const ARRAY_TYPE(seq_range) *changed_uids_arr)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	const struct seq_range *changed_uids;
	unsigned int changed_count, changed_idx;
	uint32_t next_uid;
	int ret;

	changed_uids = array_get(changed_uids_arr, &changed_count);
	i_assert(changed_count > 0);
	next_uid = changed_uids[0].seq1;
	changed_idx = 0;

	mail_search_args_init(result->search_args, result->box, FALSE, NULL);

	t = mailbox_transaction_begin(result->box, 0);
	search_ctx = mailbox_search_init(t, result->search_args, NULL);
	/* tell search that we're updating an existing search result,
	   so it can do some optimizations based on it */
	search_ctx->update_result = result;

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		i_assert(next_uid != 0);

		if (next_uid != mail->uid) {
			/* some messages in changed_uids didn't match.
			   make sure they don't exist in the search result. */
			search_result_range_remove(result, changed_uids_arr,
						   &changed_idx, &next_uid,
						   mail->uid-1);
			i_assert(next_uid == mail->uid);
		}
		if (changed_uids[changed_idx].seq2 > next_uid) {
			next_uid++;
		} else if (++changed_idx < changed_count) {
			next_uid = changed_uids[changed_idx].seq1;
		} else {
			/* this was the last searched message */
			next_uid = 0;
		}
		/* match - make sure it exists in search result */
		mailbox_search_result_add(result, mail->uid);
	}
	mail_free(&mail);
	mail_search_args_deinit(result->search_args);
	ret = mailbox_search_deinit(&search_ctx);

	if (next_uid != 0 && ret == 0) {
		/* last message(s) didn't match. make sure they don't exist
		   in the search result. */
		search_result_range_remove(result, changed_uids_arr,
					   &changed_idx, &next_uid,
					   changed_uids[changed_count-1].seq2);
	}

	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	return ret;
}

int index_search_result_update_flags(struct mail_search_result *result,
				     const ARRAY_TYPE(seq_range) *uids)
{
	struct mail_search_arg search_arg;
	int ret;

	if (array_count(uids) == 0)
		return 0;

	/* add a temporary search parameter to limit the search only to
	   the changed messages */
	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_UIDSET;
	search_arg.value.seqset = *uids;
	search_arg.next = result->search_args->args;
	result->search_args->args = &search_arg;
	ret = search_result_update_search(result, uids);
	i_assert(result->search_args->args == &search_arg);
	result->search_args->args = search_arg.next;
	return ret;
}

int index_search_result_update_appends(struct mail_search_result *result,
				       unsigned int old_messages_count)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct mail_search_arg search_arg;
	uint32_t message_count;
	int ret;

	message_count = mail_index_view_get_messages_count(result->box->view);
	if (old_messages_count == message_count) {
		/* no new messages */
		return 0;
	}

	/* add a temporary search parameter to limit the search only to
	   the new messages */
	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_SEQSET;
	t_array_init(&search_arg.value.seqset, 1);
	seq_range_array_add_range(&search_arg.value.seqset,
				  old_messages_count + 1, message_count);
	search_arg.next = result->search_args->args;
	result->search_args->args = &search_arg;

	/* add all messages matching the search to search result */
	t = mailbox_transaction_begin(result->box, 0);
	search_ctx = mailbox_search_init(t, result->search_args, NULL);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail))
		mailbox_search_result_add(result, mail->uid);
	mail_free(&mail);

	ret = mailbox_search_deinit(&search_ctx);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;

	i_assert(result->search_args->args == &search_arg);
	result->search_args->args = search_arg.next;
	return ret;
}

void index_search_results_update_expunges(struct mailbox *box,
					  const ARRAY_TYPE(seq_range) *expunges)
{
	const struct seq_range *seqs;
	uint32_t seq, uid;

	if (array_count(&box->search_results) == 0)
		return;

	array_foreach(expunges, seqs) {
		for (seq = seqs->seq1; seq <= seqs->seq2; seq++) {
			mail_index_lookup_uid(box->view, seq, &uid);
			mailbox_search_results_remove(box, uid);
		}
	}
}
