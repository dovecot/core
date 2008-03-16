/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "mail-search-build.h"
#include "imap-search.h"
#include "imap-parser.h"
#include "imap-messageset.h"

#include <stdlib.h>

struct search_build_data {
	pool_t pool;
        struct mailbox *box;
	const char *error;
};

static bool search_args_have_searchres(struct mail_search_arg *sargs)
{
	for (; sargs != NULL; sargs = sargs->next) {
		switch (sargs->type) {
		case SEARCH_UIDSET:
			if (strcmp(sargs->value.str, "$") == 0)
				return TRUE;
			break;
		case SEARCH_SUB:
		case SEARCH_OR:
			if (search_args_have_searchres(sargs->value.subargs))
				return TRUE;
			break;
		default:
			break;
		}
	}
	return FALSE;
}

int imap_search_args_build(struct client_command_context *cmd,
			   const struct imap_arg *args,
			   struct mail_search_arg **search_args_r)
{
	struct mail_search_arg *sargs;
	const char *error;

	sargs = mail_search_build_from_imap_args(cmd->pool, args, &error);
	if (sargs == NULL) {
		client_send_command_error(cmd, error);
		return -1;
	}

	if (search_args_have_searchres(sargs)) {
		if (client_handle_search_save_ambiguity(cmd))
			return 0;
	}

	mail_search_args_init(sargs, cmd->client->mailbox, TRUE,
			      &cmd->client->search_saved_uidset);
	*search_args_r = sargs;
	return 1;
}

static bool
msgset_is_valid(ARRAY_TYPE(seq_range) *seqset, uint32_t messages_count)
{
	const struct seq_range *range;
	unsigned int count;

	/* when there are no messages, all messagesets are invalid.
	   if there's at least one message:
	    - * gives seq1 = seq2 = (uint32_t)-1
	    - n:* should work if n <= messages_count
	    - n:m or m should work if m <= messages_count
	*/
	range = array_get(seqset, &count);
	if (count == 0 || messages_count == 0)
		return FALSE;

	if (range[count-1].seq2 == (uint32_t)-1) {
		if (range[count-1].seq1 > messages_count &&
		    range[count-1].seq1 != (uint32_t)-1)
			return FALSE;
	} else {
		if (range[count-1].seq2 > messages_count)
			return FALSE;
	}
	return TRUE;
}

static int imap_search_get_msgset_arg(struct client_command_context *cmd,
				      const char *messageset,
				      struct mail_search_arg **arg_r,
				      const char **error_r)
{
	struct mail_search_arg *arg;

	arg = p_new(cmd->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_SEQSET;
	p_array_init(&arg->value.seqset, cmd->pool, 16);
	if (imap_messageset_parse(&arg->value.seqset, messageset) < 0 ||
	    !msgset_is_valid(&arg->value.seqset, cmd->client->messages_count)) {
		*error_r = "Invalid messageset";
		return -1;
	}
	*arg_r = arg;
	return 0;
}

static int
imap_search_get_uidset_arg(struct client_command_context *cmd,
			   const char *uidset,
			   struct mail_search_arg **arg_r, const char **error_r)
{
	struct mail_search_arg *arg;

	arg = p_new(cmd->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_UIDSET;
	p_array_init(&arg->value.seqset, cmd->pool, 16);
	if (imap_messageset_parse(&arg->value.seqset, uidset) < 0) {
		*error_r = "Invalid uidset";
		return -1;
	}

	*arg_r = arg;
	return 0;
}

int imap_search_get_seqset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_arg **search_arg_r)
{
	int ret;

	ret = imap_search_get_anyset(cmd, set, uid, search_arg_r);
	if (ret > 0) {
		mail_search_args_init(*search_arg_r,
				      cmd->client->mailbox, TRUE,
				      &cmd->client->search_saved_uidset);
	}
	return ret;
}

static int imap_search_get_searchres(struct client_command_context *cmd,
				     struct mail_search_arg **search_arg_r)
{
	struct mail_search_arg *search_arg;

	if (client_handle_search_save_ambiguity(cmd))
		return 0;
	search_arg = p_new(cmd->pool, struct mail_search_arg, 1);
	if (array_is_created(&cmd->client->search_saved_uidset)) {
		search_arg->type = SEARCH_UIDSET;
		p_array_init(&search_arg->value.seqset, cmd->pool,
			     array_count(&cmd->client->search_saved_uidset));
		array_append_array(&search_arg->value.seqset,
				   &cmd->client->search_saved_uidset);
	} else {
		/* $ not set yet, match nothing */
		search_arg->type = SEARCH_ALL;
		search_arg->not = TRUE;
	}
	*search_arg_r = search_arg;
	return 1;
}

int imap_search_get_anyset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_arg **search_arg_r)
{
	const char *error = NULL;
	int ret;

	if (strcmp(set, "$") == 0) {
		/* SEARCHRES extension: replace $ with the last saved
		   search result */
		return imap_search_get_searchres(cmd, search_arg_r);
	}
	if (!uid)
		ret = imap_search_get_msgset_arg(cmd, set, search_arg_r, &error);
	else
		ret = imap_search_get_uidset_arg(cmd, set, search_arg_r, &error);
	if (ret < 0) {
		client_send_command_error(cmd, error);
		return -1;
	}
	return 1;
}
