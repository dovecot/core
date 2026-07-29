/* Copyright (c) Dovecot authors, see top-level COPYING file */

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
#include "imapc-sync.h"
#include "index-sort.h"

#define IMAPC_SEARCHCTX(obj) \
	MODULE_CONTEXT(obj, imapc_storage_module)

ARRAY_DEFINE_TYPE(imapc_search_arg, struct mail_search_arg *);

static bool
imapc_build_search_query_args(struct imapc_mailbox *mbox,
			      const struct mail_search_arg *args,
			      bool parent_or, string_t *str);
static bool
imapc_build_search_query_toplevel(struct imapc_mailbox *mbox,
				  struct mail_search_args *args,
				  ARRAY_TYPE(imapc_search_arg) *sent_args,
				  string_t *str);
static void imapc_search_set_matches(struct mail_search_arg *arg);

static bool
imapc_build_sort_query(struct imapc_mailbox *mbox,
		       struct mail_search_args *args,
		       const enum mail_sort_type *sort_program,
		       ARRAY_TYPE(imapc_search_arg) *sent_args,
		       const char **query_r)
{
	string_t *str = t_str_new(128);
	const char *charset = "UTF-8";
	unsigned int i;

	if ((mbox->capabilities & IMAPC_CAPABILITY_SORT) == 0) {
		/* SORT command passthrough not possible */
		return FALSE;
	}
	if (args->args != NULL &&
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_SEARCH)) {
		/* Evaluating search criteria on the remote server isn't
		   allowed. Sorting without any criteria is still fine. */
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

	if (args->args == NULL ||
	    !imapc_build_search_query_toplevel(mbox, args, sent_args, str)) {
		/* No search criteria could be sent to the remote server, but
		   the sorting itself still can be. */
		str_append(str, "ALL");
	}
	*query_r = str_c(str);
	return TRUE;
}


struct imapc_search_context {
	union mail_search_module_context module_ctx;

	ARRAY_TYPE(seq_range) uids;
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
		return imapc_build_search_query_args(mbox, arg->value.subargs,
						    TRUE, str);
	case SEARCH_SUB:
		str_append_c(str, '(');
		if (!imapc_build_search_query_args(mbox, arg->value.subargs,
						   FALSE, str))
			return FALSE;
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

static bool
imapc_build_search_query_toplevel(struct imapc_mailbox *mbox,
				  struct mail_search_args *args,
				  ARRAY_TYPE(imapc_search_arg) *sent_args,
				  string_t *str)
{
	struct mail_search_arg *arg;
	size_t pos;

	/* The top-level args are ANDed together, so leaving out some of them
	   only makes the remote return a superset of the wanted mails. The
	   left out args are evaluated locally. This can't be done for args
	   deeper in the tree, where dropping an arg could lose mails.

	   The args are already simplified by mailbox_search_init(), which
	   flattens non-negated sub-searches into this list and lifts args
	   that are common to all OR branches up to here, so most args end up
	   being handled individually. */
	for (arg = args->args; arg != NULL; arg = arg->next) {
		pos = str_len(str);
		if (!imapc_build_search_query_arg(mbox, arg, str)) {
			str_truncate(str, pos);
			continue;
		}
		str_append_c(str, ' ');
		array_push_back(sent_args, &arg);
	}
	if (array_count(sent_args) == 0)
		return FALSE;
	str_truncate(str, str_len(str)-1);
	return TRUE;
}

static bool imapc_build_search_query(struct imapc_mailbox *mbox,
				     struct mail_search_args *args,
				     ARRAY_TYPE(imapc_search_arg) *sent_args,
				     const char **query_r)
{
	string_t *str = t_str_new(128);

	if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_SEARCH)) {
		/* SEARCH command passthrough not enabled */
		return FALSE;
	}
	if (imapc_search_is_fast_local(args->args))
		return FALSE;

	str_append(str, "UID SEARCH ");
	if ((mbox->capabilities & IMAPC_CAPABILITY_ESEARCH) != 0)
		str_append(str, "RETURN (ALL) ");
	if (!imapc_build_search_query_toplevel(mbox, args, sent_args, str))
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
		seq_range_array_iter_init(&ictx->iter, &ictx->uids);
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
	struct mail_search_arg *arg;
	ARRAY_TYPE(imapc_search_arg) sent_args;
	const char *search_query;

	t_array_init(&sent_args, 8);
	if (sort_program != NULL &&
	    imapc_build_sort_query(mbox, args, sort_program, &sent_args,
				   &search_query)) {
		ctx = index_storage_search_init(t, args, NULL,
						wanted_fields, wanted_headers);
		ictx = i_new(struct imapc_search_context, 1);
		ictx->sorted = TRUE;
	} else {
		array_clear(&sent_args);
		ctx = index_storage_search_init(t, args, sort_program,
						wanted_fields, wanted_headers);
		if (!imapc_build_search_query(mbox, args, &sent_args,
					      &search_query)) {
			/* can't optimize this with SEARCH */
			return ctx;
		}
		ictx = i_new(struct imapc_search_context, 1);
	}
	i_array_init(&ictx->uids, 64);
	i_array_init(&ictx->sorted_uids, 64);
	MODULE_CONTEXT_SET(ctx, imapc_storage_module, ictx);

	/* flush locally cached flag changes to the remote so that the
	   passed-through SEARCH/SORT evaluates the up-to-date flags. If this
	   fails, leave ictx->success=FALSE so that imapc_search_deinit()
	   returns the error to the client instead of returning stale
	   results. */
	if (imapc_mailbox_flush_local_flag_changes(mbox) < 0)
		return ctx;

	/* the remote server evaluates these args - the rest are evaluated
	   locally while returning the results */
	array_foreach_elem(&sent_args, arg)
		imapc_search_set_matches(arg);

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

static void imapc_search_set_matches(struct mail_search_arg *arg)
{
	struct mail_search_arg *subarg;

	if (arg->type == SEARCH_OR || arg->type == SEARCH_SUB) {
		for (subarg = arg->value.subargs; subarg != NULL;
		     subarg = subarg->next)
			imapc_search_set_matches(subarg);
	}
	arg->match_always = TRUE;
	arg->result = 1;
}

static bool
imapc_search_next_uid(struct mail_search_context *ctx, uint32_t uid)
{
	/* The remote sequences may have changed while the results were being
	   handled, so map the UID to the local sequence only now. Messages
	   that aren't in the local index yet aren't visible to the client
	   either, so they're skipped. */
	if (!mail_index_lookup_seq(ctx->transaction->view, uid, &ctx->seq))
		return FALSE;
	ctx->progress_cur = ctx->seq;
	/* The args that were sent to the remote server are already marked as
	   matched. Evaluate the rest of the args that can be looked up from
	   the index. */
	if (!index_storage_search_match_index_args(ctx)) {
		/* This mail didn't match. Clear the arg results that were
		   just set, so the next mail is evaluated from a clean state.
		   The failed lookup above doesn't need this, because then no
		   args were evaluated yet. */
		mail_search_args_reset(ctx->args->args, FALSE);
		return FALSE;
	}
	return TRUE;
}

bool imapc_search_next_update_seq(struct mail_search_context *ctx)
{
	struct imapc_search_context *ictx = IMAPC_SEARCHCTX(ctx);
	const uint32_t *uidp;
	uint32_t uid;

	if (ictx == NULL || !ictx->success)
		return index_storage_search_next_update_seq(ctx);

	if (ictx->sorted) {
		while (ictx->n < array_count(&ictx->sorted_uids)) {
			uidp = array_idx(&ictx->sorted_uids, ictx->n++);
			if (imapc_search_next_uid(ctx, *uidp))
				return TRUE;
		}
		return FALSE;
	}

	while (seq_range_array_iter_nth(&ictx->iter, ictx->n++, &uid)) {
		if (imapc_search_next_uid(ctx, uid))
			return TRUE;
	}
	return FALSE;
}

int imapc_search_deinit(struct mail_search_context *ctx)
{
	struct imapc_search_context *ictx = IMAPC_SEARCHCTX(ctx);
	int ret = 0;

	if (ictx != NULL) {
		if (!ictx->success)
			ret = -1;
		array_free(&ictx->uids);
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
	const char *atom;
	uint32_t uid;

	if (mbox->search_ctx == NULL || mbox->search_ctx->sorted) {
		e_error(event, "Unexpected SEARCH reply");
		return;
	}

	/* we're doing UID SEARCH, so the reply contains UIDs. They're mapped
	   to the local sequences only while returning the results, because
	   the remote sequences may change while the results are being
	   handled. */
	for (unsigned int i = 0; args[i].type != IMAP_ARG_EOL; i++) {
		if (!imap_arg_get_atom(&args[i], &atom) ||
		    str_to_uint32(atom, &uid) < 0 || uid == 0) {
			e_error(event, "Invalid SEARCH reply");
			break;
		}
		seq_range_array_add(&mbox->search_ctx->uids, uid);
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

	/* It should contain UID ALL <uidset> or just UID if nothing matched */
	if (!imap_arg_atom_equals(&args[0], "UID") ||
	    (args[1].type != IMAP_ARG_EOL &&
	     (!imap_arg_atom_equals(&args[1], "ALL") ||
	      !imap_arg_get_atom(&args[2], &atom) ||
	      imap_seq_set_nostar_parse(atom, &mbox->search_ctx->uids) < 0)))
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
