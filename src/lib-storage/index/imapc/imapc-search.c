/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "mail-search.h"
#include "imapc-msgmap.h"
#include "imapc-storage.h"
#include "imapc-search.h"

#define IMAPC_SEARCHCTX(obj) \
	MODULE_CONTEXT(obj, imapc_storage_module)

struct imapc_search_context {
	union mail_search_module_context module_ctx;

	ARRAY_TYPE(seq_range) rseqs;
	struct seq_range_iter iter;
	unsigned int n;
	bool finished;
	bool success;
};

static MODULE_CONTEXT_DEFINE_INIT(imapc_storage_module,
				  &mail_storage_module_register);

static bool
imapc_build_search_query_args(struct imapc_mailbox *mbox,
			      const struct mail_search_arg *args,
			      bool parent_or, string_t *str);

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
		if ((mbox->capabilities & IMAPC_CAPABILITY_WITHIN) == 0) {
			/* a bit kludgy way to check this.. */
			size_t pos = str_len(str);
			if (!mail_search_arg_to_imap(str, arg, &error))
				return FALSE;
			if (strncasecmp(str_c(str) + pos, "OLDER", 5) == 0 ||
			    strncasecmp(str_c(str) + pos, "YOUNGER", 7) == 0)
				return FALSE;
			return TRUE;
		}
		/* fall through */
	case SEARCH_ALL:
	case SEARCH_UIDSET:
	case SEARCH_FLAGS:
	case SEARCH_KEYWORDS:
	case SEARCH_ON:
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
	case SEARCH_BODY:
	case SEARCH_TEXT:
		return mail_search_arg_to_imap(str, arg, &error);
	/* extensions */
	case SEARCH_MODSEQ:
		if ((mbox->capabilities & IMAPC_CAPABILITY_CONDSTORE) == 0)
			return FALSE;
		return mail_search_arg_to_imap(str, arg, &error);
	case SEARCH_SAVEDATESUPPORTED:
	case SEARCH_INTHREAD:
	case SEARCH_GUID:
	case SEARCH_MAILBOX:
	case SEARCH_MAILBOX_GUID:
	case SEARCH_MAILBOX_GLOB:
	case SEARCH_REAL_UID:
	case SEARCH_MIMEPART:
		/* not supported for now */
		break;
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

	if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_SEARCH)) {
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

	ctx = index_storage_search_init(t, args, sort_program,
					wanted_fields, wanted_headers);

	if (!imapc_build_search_query(mbox, args, &search_query)) {
		/* can't optimize this with SEARCH */
		return ctx;
	}

	ictx = i_new(struct imapc_search_context, 1);
	i_array_init(&ictx->rseqs, 64);
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

	if (ictx == NULL || !ictx->success)
		return index_storage_search_next_update_seq(ctx);

	if (!seq_range_array_iter_nth(&ictx->iter, ictx->n++, &ctx->seq))
		return FALSE;
	ctx->progress_cur = ctx->seq;

	imapc_search_set_matches(ctx->args->args);
	return TRUE;
}

int imapc_search_deinit(struct mail_search_context *ctx)
{
	struct imapc_search_context *ictx = IMAPC_SEARCHCTX(ctx);

	if (ictx != NULL) {
		array_free(&ictx->rseqs);
		i_free(ictx);
	}
	return index_storage_search_deinit(ctx);
}

void imapc_search_reply_search(const struct imap_arg *args,
			       struct imapc_mailbox *mbox)
{
	struct imapc_msgmap *msgmap =
		imapc_client_mailbox_get_msgmap(mbox->client_box);
	const char *atom;
	uint32_t uid, rseq;

	if (mbox->search_ctx == NULL) {
		i_error("Unexpected SEARCH reply");
		return;
	}

	/* we're doing UID SEARCH, so need to convert UIDs to sequences */
	for (unsigned int i = 0; args[i].type != IMAP_ARG_EOL; i++) {
		if (!imap_arg_get_atom(&args[i], &atom) ||
		    str_to_uint32(atom, &uid) < 0 || uid == 0) {
			i_error("Invalid SEARCH reply");
			break;
		}
		if (imapc_msgmap_uid_to_rseq(msgmap, uid, &rseq))
			seq_range_array_add(&mbox->search_ctx->rseqs, rseq);
	}
}

void imapc_search_reply_esearch(const struct imap_arg *args,
				struct imapc_mailbox *mbox)
{
	const char *atom;

	if (mbox->search_ctx == NULL) {
		i_error("Unexpected ESEARCH reply");
		return;
	}

	/* It should contain ALL <seqset> or nonexistent if nothing matched */
	if (args[0].type != IMAP_ARG_EOL &&
	    (!imap_arg_atom_equals(&args[0], "ALL") ||
	     !imap_arg_get_atom(&args[1], &atom) ||
	     imap_seq_set_nostar_parse(atom, &mbox->search_ctx->rseqs) < 0))
		i_error("Invalid ESEARCH reply");
}
