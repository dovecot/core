/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-search.h"
#include "index-storage.h"
#include "virtual-storage.h"

#include <stdlib.h>

enum virtual_search_state {
	VIRTUAL_SEARCH_STATE_BUILD,
	VIRTUAL_SEARCH_STATE_RETURN,
	VIRTUAL_SEARCH_STATE_SORT,
	VIRTUAL_SEARCH_STATE_SORT_DONE
};

struct virtual_search_record {
	uint32_t mailbox_id;
	uint32_t real_uid;
	uint32_t virtual_seq;
};

struct virtual_search_context {
	union mail_search_module_context module_ctx;

	ARRAY_TYPE(seq_range) result;
	struct seq_range_iter result_iter;
	ARRAY_DEFINE(records, struct virtual_search_record);

	enum virtual_search_state search_state;
	unsigned int next_result_n;
	unsigned int next_record_idx;
};

static int virtual_search_record_cmp(const struct virtual_search_record *r1,
				     const struct virtual_search_record *r2)
{
	if (r1->mailbox_id < r2->mailbox_id)
		return -1;
	if (r1->mailbox_id > r2->mailbox_id)
		return 1;

	if (r1->real_uid < r2->real_uid)
		return -1;
	if (r1->real_uid > r2->real_uid)
		return 1;
	return 0;
}

static int mail_search_get_result(struct mail_search_context *ctx)
{
	const struct mail_search_arg *arg;
	int ret = 1;

	for (arg = ctx->args->args; arg != NULL; arg = arg->next) {
		if (arg->result < 0)
			return -1;
		if (arg->result == 0)
			ret = 0;
	}
	return ret;
}

static void virtual_search_get_records(struct mail_search_context *ctx,
				       struct virtual_search_context *vctx)
{
	struct virtual_mailbox *mbox =
		(struct virtual_mailbox *)ctx->transaction->box;
	const struct virtual_mail_index_record *vrec;
	struct virtual_search_record srec;
	const void *data;
	bool expunged;
	int result;

	memset(&srec, 0, sizeof(srec));
	while (index_storage_search_next_update_seq(ctx)) {
		result = mail_search_get_result(ctx);
		i_assert(result != 0);
		if (result > 0) {
			/* full match, no need to check this any further */
			seq_range_array_add(&vctx->result, 0, ctx->seq);
		} else {
			/* possible match, save and check later */
			mail_index_lookup_ext(mbox->box.view, ctx->seq,
					      mbox->virtual_ext_id,
					      &data, &expunged);
			vrec = data;

			srec.mailbox_id = vrec->mailbox_id;
			srec.real_uid = vrec->real_uid;
			srec.virtual_seq = ctx->seq;
			array_append(&vctx->records, &srec, 1);
		}
		mail_search_args_reset(ctx->args->args, FALSE);
	}
	array_sort(&vctx->records, virtual_search_record_cmp);

	ctx->progress_max = array_count(&vctx->records);
}

struct mail_search_context *
virtual_search_init(struct mailbox_transaction_context *t,
		    struct mail_search_args *args,
		    const enum mail_sort_type *sort_program)
{
	struct mail_search_context *ctx;
	struct virtual_search_context *vctx;

	ctx = index_storage_search_init(t, args, sort_program);

	vctx = i_new(struct virtual_search_context, 1);
	vctx->search_state = VIRTUAL_SEARCH_STATE_BUILD;
	i_array_init(&vctx->result, 64);
	i_array_init(&vctx->records, 64);
	MODULE_CONTEXT_SET(ctx, virtual_storage_module, vctx);

	virtual_search_get_records(ctx, vctx);
	seq_range_array_iter_init(&vctx->result_iter, &vctx->result);
	return ctx;
}

int virtual_search_deinit(struct mail_search_context *ctx)
{
	struct virtual_search_context *vctx = VIRTUAL_CONTEXT(ctx);

	array_free(&vctx->result);
	array_free(&vctx->records);
	i_free(vctx);
	return index_storage_search_deinit(ctx);
}

bool virtual_search_next_nonblock(struct mail_search_context *ctx,
				  struct mail *mail, bool *tryagain_r)
{
	struct virtual_search_context *vctx = VIRTUAL_CONTEXT(ctx);
	uint32_t seq;

	switch (vctx->search_state) {
	case VIRTUAL_SEARCH_STATE_BUILD:
		if (ctx->sort_program == NULL)
			vctx->search_state = VIRTUAL_SEARCH_STATE_SORT;
		else
			vctx->search_state = VIRTUAL_SEARCH_STATE_RETURN;
		return virtual_search_next_nonblock(ctx, mail, tryagain_r);
	case VIRTUAL_SEARCH_STATE_RETURN:
		return index_storage_search_next_nonblock(ctx, mail, tryagain_r);
	case VIRTUAL_SEARCH_STATE_SORT:
		/* the messages won't be returned sorted, so we'll have to
		   do it ourself */
		while (index_storage_search_next_nonblock(ctx, mail, tryagain_r))
			seq_range_array_add(&vctx->result, 0, mail->seq);
		if (*tryagain_r)
			return FALSE;

		vctx->next_result_n = 0;
		vctx->search_state = VIRTUAL_SEARCH_STATE_SORT_DONE;
		/* fall through */
	case VIRTUAL_SEARCH_STATE_SORT_DONE:
		*tryagain_r = FALSE;
		if (!seq_range_array_iter_nth(&vctx->result_iter,
					      vctx->next_result_n, &seq))
			return FALSE;
		vctx->next_result_n++;
		mail_set_seq(mail, seq);
		return TRUE;
	}
	i_unreached();
}

static void search_args_set_full_match(struct mail_search_arg *args)
{
	for (; args != NULL; args = args->next)
		args->result = 1;
}

bool virtual_search_next_update_seq(struct mail_search_context *ctx)
{
	struct virtual_search_context *vctx = VIRTUAL_CONTEXT(ctx);
	const struct virtual_search_record *recs;
	unsigned int count;

	recs = array_get(&vctx->records, &count);
	if (vctx->next_record_idx < count) {
		/* go through potential results first */
		ctx->seq = recs[vctx->next_record_idx++].virtual_seq - 1;
		if (!index_storage_search_next_update_seq(ctx))
			i_unreached();
		ctx->progress_cur = vctx->next_record_idx;
		return TRUE;
	}

	if (ctx->sort_program != NULL &&
	    seq_range_array_iter_nth(&vctx->result_iter,
				     vctx->next_result_n, &ctx->seq)) {
		/* this is known to match fully */
		search_args_set_full_match(ctx->args->args);
		vctx->next_result_n++;
		return TRUE;
	}
	return FALSE;
}
