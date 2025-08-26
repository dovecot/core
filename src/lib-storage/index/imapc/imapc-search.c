/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "mail-search.h"
#include "mail-storage-private.h"
#include "imapc-msgmap.h"
#include "imapc-storage.h"
#include "imapc-search.h"
#include "index-sort.h"

#define IMAPC_SEARCHCTX(obj) \
	MODULE_CONTEXT(obj, imapc_storage_module)

static bool
imapc_build_search_query_args(struct imapc_mailbox *mbox,
			      const struct mail_search_arg *args,
			      bool parent_or, string_t *str);

static bool
imapc_build_sort_query(struct imapc_mailbox *mbox,
		       const struct mail_search_args *args,
		       const enum mail_sort_type *sort_program,
		       const char **query_r)
{
	string_t *str = t_str_new(128);
	const char *charset = "UTF-8";
	unsigned int i;

	if ((mbox->capabilities & IMAPC_CAPABILITY_SORT) == 0) {
		/* SORT command passthrough not possible */
		return FALSE;
	}

	str_append(str, "UID SORT ");
	if ((mbox->capabilities & IMAPC_CAPABILITY_ESORT) != 0)
		str_append(str, "RETURN (ALL) ");
	str_append_c(str, '(');
	for (i = 0; sort_program[i] != MAIL_SORT_END; i++) {
		if ((sort_program[i] & MAIL_SORT_FLAG_REVERSE) != 0)
			str_append(str, "REVERSE ");
		switch (sort_program[i] & MAIL_SORT_MASK) {
		case MAIL_SORT_ARRIVAL:
			str_append(str, "ARRIVAL");
			break;
		case MAIL_SORT_CC:
			str_append(str, "CC");
			break;
		case MAIL_SORT_DATE:
			str_append(str, "DATE");
			break;
		case MAIL_SORT_FROM:
			str_append(str, "FROM");
			break;
		case MAIL_SORT_SIZE:
			str_append(str, "SIZE");
			break;
		case MAIL_SORT_SUBJECT:
			str_append(str, "SUBJECT");
			break;
		case MAIL_SORT_TO:
			str_append(str, "TO");
			break;
		case MAIL_SORT_DISPLAYFROM:
			if ((mbox->capabilities & IMAPC_CAPABILITY_SORT_DISPLAY) == 0)
				return FALSE;
			str_append(str, "DISPLAYFROM");
			break;
		case MAIL_SORT_DISPLAYTO:
			if ((mbox->capabilities & IMAPC_CAPABILITY_SORT_DISPLAY) == 0)
				return FALSE;
			str_append(str, "DISPLAYTO");
			break;
		case MAIL_SORT_RELEVANCY:
		case MAIL_SORT_POP3_ORDER:
			return FALSE;
		default:
			i_unreached();
		}
		if (sort_program[i+1] != MAIL_SORT_END)
			str_append_c(str, ' ');
	}
	str_append(str, ") ");
	str_append(str, charset);
	str_append_c(str, ' ');

	if (args->args == NULL)
		str_append(str, "ALL");
	else if (!imapc_build_search_query_args(mbox, args->args, FALSE, str))
		return FALSE;
	*query_r = str_c(str);
	return TRUE;
}


struct imapc_search_context {
	union mail_search_module_context module_ctx;

	ARRAY_TYPE(seq_range) rseqs;
	ARRAY_TYPE(uint32_t) sorted_uids;
	struct seq_range_iter iter;
	unsigned int n;
	bool finished;
	bool success;
	bool sorted;
};

static MODULE_CONTEXT_DEFINE_INIT(imapc_storage_module,
				  &mail_storage_module_register);

static bool imapc_search_is_fast_local(const struct mail_search_arg *args)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
			if (!imapc_search_is_fast_local(arg->value.subargs))
				return FALSE;
			break;
		case SEARCH_ALL:
		case SEARCH_SEQSET:
		case SEARCH_UIDSET:
		case SEARCH_FLAGS:
		case SEARCH_KEYWORDS:
		case SEARCH_MODSEQ:
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GUID:
		case SEARCH_MAILBOX_GLOB:
		case SEARCH_REAL_UID:
			break;
		default:
			return FALSE;
		}
	}
	return TRUE;
}

static bool
imapc_build_search_query_arg(struct imapc_mailbox *mbox,
			     const struct mail_search_arg *arg,
			     string_t *str)
{
	struct mail_search_arg arg2 = *arg;
	const char *error;

	if (arg->match_not)
		str_append(str, "NOT ");
	arg2.match_not = FALSE;
	arg = &arg2;

	switch (arg->type) {
	case SEARCH_OR:
		imapc_build_search_query_args(mbox, arg->value.subargs, TRUE, str);
		return TRUE;
	case SEARCH_SUB:
		str_append_c(str, '(');
		imapc_build_search_query_args(mbox, arg->value.subargs, FALSE, str);
		str_append_c(str, ')');
		return TRUE;
	case SEARCH_SEQSET:
		/* translate to UIDs */
		T_BEGIN {
			ARRAY_TYPE(seq_range) uids;

			t_array_init(&uids, 64);
			mailbox_get_uid_range(&mbox->box, &arg->value.seqset,
					      &uids);
			str_append(str, "UID ");
			imap_write_seq_range(str, &uids);
		} T_END;
		return TRUE;
	case SEARCH_BEFORE:
	case SEARCH_SINCE:
	case SEARCH_ON:
		if (arg->type != SEARCH_ON &&
		    (mbox->capabilities & IMAPC_CAPABILITY_WITHIN) == 0) {
			/* a bit kludgy way to check this.. */
			size_t pos = str_len(str);
			if (!mail_search_arg_to_imap(str, arg, FALSE, &error))
				return FALSE;
			if (str_begins_icase_with(str_c(str) + pos, "OLDER") ||
			    str_begins_icase_with(str_c(str) + pos, "YOUNGER"))
				return FALSE;
			return TRUE;
		}
		if (arg->value.date_type == MAIL_SEARCH_DATE_TYPE_SAVED &&
		    (mbox->capabilities & IMAPC_CAPABILITY_SAVEDATE) == 0) {
			/* Fall back to internal date if save date is not
			   supported. */
			arg2.value.date_type = MAIL_SEARCH_DATE_TYPE_RECEIVED;
		}
		/* fall through */
	case SEARCH_ALL:
	case SEARCH_UIDSET:
	case SEARCH_FLAGS:
	case SEARCH_KEYWORDS:
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
	case SEARCH_BODY:
	case SEARCH_TEXT:
		return mail_search_arg_to_imap(str, arg, FALSE, &error);
	/* extensions */
	case SEARCH_MODSEQ:
		if ((mbox->capabilities & IMAPC_CAPABILITY_CONDSTORE) == 0)
			return FALSE;
		return mail_search_arg_to_imap(str, arg, FALSE, &error);
	case SEARCH_SAVEDATESUPPORTED:
		if ((mbox->capabilities & IMAPC_CAPABILITY_SAVEDATE) == 0)
			return FALSE;
		return mail_search_arg_to_imap(str, arg, FALSE, &error);
	case SEARCH_INTHREAD:
	case SEARCH_GUID:
	case SEARCH_MAILBOX:
	case SEARCH_MAILBOX_GUID:
	case SEARCH_MAILBOX_GLOB:
	case SEARCH_REAL_UID:
		/* not supported for now */
		break;
	case SEARCH_MIMEPART:
		if ((mbox->capabilities & IMAPC_CAPABILITY_SEARCH_MIMEPART) == 0)
			return FALSE;
		return mail_search_arg_to_imap(str, arg, FALSE, &error);
	}
	return FALSE;
}

static bool
imapc_build_search_query_args(struct imapc_mailbox *mbox,
			      const struct mail_search_arg *args,
			      bool parent_or, string_t *str)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (parent_or && arg->next != NULL)
			str_append(str, "OR ");
		if (!imapc_build_search_query_arg(mbox, arg, str))
			return FALSE;
		str_append_c(str, ' ');
	}
	str_truncate(str, str_len(str)-1);
	return TRUE;
}

static bool imapc_build_search_query(struct imapc_mailbox *mbox,
				     const struct mail_search_args *args,
				     const char **query_r)
{
	string_t *str = t_str_new(128);

	if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_SEARCH)) {
		/* SEARCH command passthrough not enabled */
		return FALSE;
	}
	if (imapc_search_is_fast_local(args->args))
		return FALSE;

	if ((mbox->capabilities & IMAPC_CAPABILITY_ESEARCH) != 0)
		str_append(str, "SEARCH RETURN (ALL) ");
	else
		str_append(str, "UID SEARCH ");
	if (!imapc_build_search_query_args(mbox, args->args, FALSE, str))
		return FALSE;
	*query_r = str_c(str);
	return TRUE;
}

static void imapc_search_callback(const struct imapc_command_reply *reply,
				  void *context)
{
	struct mail_search_context *ctx = context;
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(ctx->transaction->box);
	struct imapc_search_context *ictx = IMAPC_SEARCHCTX(ctx);
	i_assert(ictx != NULL);

	ictx->finished = TRUE;
	if (reply->state == IMAPC_COMMAND_STATE_OK) {
		seq_range_array_iter_init(&ictx->iter, &ictx->rseqs);
		ictx->success = TRUE;
	} else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(mbox->storage, MAIL_ERROR_PARAMS,
					    reply);
	} else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED) {
		mail_storage_set_internal_error(mbox->box.storage);
	} else {
		mailbox_set_critical(&mbox->box,
			"imapc: Command failed: %s", reply->text_full);
	}
	imapc_client_stop(mbox->storage->client->client);
}

struct mail_search_context *
imapc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(t->box);
	struct mail_search_context *ctx;
	struct imapc_search_context *ictx;
	struct imapc_command *cmd;
	const char *search_query;

	if (sort_program != NULL &&
	    imapc_build_sort_query(mbox, args, sort_program, &search_query)) {
		ctx = index_storage_search_init(t, args, NULL,
						wanted_fields, wanted_headers);
		ictx = i_new(struct imapc_search_context, 1);
		ictx->sorted = TRUE;
	} else {
		ctx = index_storage_search_init(t, args, sort_program,
						wanted_fields, wanted_headers);
		if (!imapc_build_search_query(mbox, args, &search_query)) {
			/* can't optimize this with SEARCH */
			return ctx;
		}
		ictx = i_new(struct imapc_search_context, 1);
	}
	i_array_init(&ictx->rseqs, 64);
	i_array_init(&ictx->sorted_uids, 64);
	MODULE_CONTEXT_SET(ctx, imapc_storage_module, ictx);

	cmd = imapc_client_mailbox_cmd(mbox->client_box,
				       imapc_search_callback, ctx);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, search_query);

	i_assert(mbox->search_ctx == NULL);
	mbox->search_ctx = ictx;
	while (!ictx->finished)
		imapc_client_run(mbox->storage->client->client);
	mbox->search_ctx = NULL;
	return ctx;
}

static void imapc_search_set_matches(struct mail_search_arg *args)
{
	for (; args != NULL; args = args->next) {
		if (args->type == SEARCH_OR ||
		    args->type == SEARCH_SUB)
			imapc_search_set_matches(args->value.subargs);
		args->match_always = TRUE;
		args->result = 1;
	}
}

bool imapc_search_next_update_seq(struct mail_search_context *ctx)
{
	struct imapc_search_context *ictx = IMAPC_SEARCHCTX(ctx);
	const uint32_t *uidp;

	if (ictx == NULL || !ictx->success)
		return index_storage_search_next_update_seq(ctx);

	if (ictx->sorted) {
		while (ictx->n < array_count(&ictx->sorted_uids)) {
			uidp = array_idx(&ictx->sorted_uids, ictx->n++);
			if (mail_index_lookup_seq(ctx->transaction->view, *uidp, &ctx->seq))
				return TRUE;
		}
		return FALSE;
	}

	if (!seq_range_array_iter_nth(&ictx->iter, ictx->n++, &ctx->seq))
		return FALSE;
	ctx->progress_cur = ctx->seq;

	imapc_search_set_matches(ctx->args->args);
	return TRUE;
}

int imapc_search_deinit(struct mail_search_context *ctx)
{
	struct imapc_search_context *ictx = IMAPC_SEARCHCTX(ctx);
	int ret = 0;

	if (ictx != NULL) {
		if (!ictx->success)
			ret = -1;
		array_free(&ictx->rseqs);
		array_free(&ictx->sorted_uids);
		i_free(ictx);
	}
	if (index_storage_search_deinit(ctx) < 0)
		return -1;
	return ret;
}

void imapc_search_reply_search(const struct imap_arg *args,
			       struct imapc_mailbox *mbox)
{
	struct event *event = mbox->box.event;
	struct imapc_msgmap *msgmap =
		imapc_client_mailbox_get_msgmap(mbox->client_box);
	const char *atom;
	uint32_t uid, rseq;

	if (mbox->search_ctx == NULL || mbox->search_ctx->sorted) {
		e_error(event, "Unexpected SEARCH reply");
		return;
	}

	/* we're doing UID SEARCH, so need to convert UIDs to sequences */
	for (unsigned int i = 0; args[i].type != IMAP_ARG_EOL; i++) {
		if (!imap_arg_get_atom(&args[i], &atom) ||
		    str_to_uint32(atom, &uid) < 0 || uid == 0) {
			e_error(event, "Invalid SEARCH reply");
			break;
		}
		if (imapc_msgmap_uid_to_rseq(msgmap, uid, &rseq))
			seq_range_array_add(&mbox->search_ctx->rseqs, rseq);
	}
}

static void imapc_search_reply_esort(const struct imap_arg *args,
				     struct imapc_mailbox *mbox)
{
	const char *atom;

	/* It should contain UID ALL <uidset> or just UID if nothing matched */
	if (!imap_arg_atom_equals(&args[0], "UID") ||
	    (args[1].type != IMAP_ARG_EOL &&
	     (!imap_arg_atom_equals(&args[1], "ALL") ||
	      !imap_arg_get_atom(&args[2], &atom) ||
	      imap_seq_set_ordered_parse(atom, &mbox->search_ctx->sorted_uids) < 0)))
		e_error(mbox->box.event, "Invalid ESEARCH reply for SORT");
}

void imapc_search_reply_esearch(const struct imap_arg *args,
				struct imapc_mailbox *mbox)
{
	struct event *event = mbox->box.event;
	const char *atom;

	if (mbox->search_ctx == NULL) {
		e_error(event, "Unexpected ESEARCH reply");
		return;
	}

	if (mbox->search_ctx->sorted) {
		imapc_search_reply_esort(args, mbox);
		return;
	}

	/* It should contain ALL <seqset> or nonexistent if nothing matched */
	if (args[0].type != IMAP_ARG_EOL &&
	    (!imap_arg_atom_equals(&args[0], "ALL") ||
	     !imap_arg_get_atom(&args[1], &atom) ||
	     imap_seq_set_nostar_parse(atom, &mbox->search_ctx->rseqs) < 0))
		e_error(event, "Invalid ESEARCH reply");
}

void imapc_search_reply_sort(const struct imap_arg *args,
			     struct imapc_mailbox *mbox)
{
	struct event *event = mbox->box.event;
	const char *atom;
	uint32_t uid;

	if (mbox->search_ctx == NULL || !mbox->search_ctx->sorted) {
		e_error(event, "Unexpected SORT reply");
		return;
	}

	for (unsigned int i = 0; args[i].type != IMAP_ARG_EOL; i++) {
		if (!imap_arg_get_atom(&args[i], &atom) ||
		    str_to_uint32(atom, &uid) < 0 || uid == 0) {
			e_error(event, "Invalid SORT reply");
			break;
		}
		array_push_back(&mbox->search_ctx->sorted_uids, &uid);
	}
}
