/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "mail-storage.h"
#include "mail-search-parser.h"
#include "mail-search-build.h"
#include "imap-search-args.h"
#include "imap-parser.h"
#include "imap-seqset.h"


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
			   const struct imap_arg *args, const char *charset,
			   struct mail_search_args **search_args_r)
{
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *client_error;
	int ret;

	if (IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Missing search parameters");
		return -1;
	}

	parser = mail_search_parser_init_imap(args);
	ret = mail_search_build(mail_search_register_get_imap(),
				parser, &charset, &sargs, &client_error);
	mail_search_parser_deinit(&parser);
	if (ret < 0) {
		if (charset == NULL) {
			client_send_tagline(cmd, t_strconcat(
				"BAD [BADCHARSET] ", client_error, NULL));
		} else {
			client_send_command_error(cmd, client_error);
		}
		return -1;
	}

	if (search_args_have_searchres(sargs->args)) {
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
				      struct mail_search_args **args_r,
				      const char **error_r)
{
	struct mail_search_args *args;

	args = mail_search_build_init();
	args->args = p_new(args->pool, struct mail_search_arg, 1);
	args->args->type = SEARCH_SEQSET;
	p_array_init(&args->args->value.seqset, args->pool, 16);
	if (imap_seq_set_parse(messageset, &args->args->value.seqset) < 0 ||
	    !msgset_is_valid(&args->args->value.seqset,
			     cmd->client->messages_count)) {
		*error_r = "Invalid messageset";
		mail_search_args_unref(&args);
		return -1;
	}
	*args_r = args;
	return 0;
}

static int
imap_search_get_uidset_arg(const char *uidset, struct mail_search_args **args_r,
			   const char **error_r)
{
	struct mail_search_args *args;

	args = mail_search_build_init();
	args->args = p_new(args->pool, struct mail_search_arg, 1);
	args->args->type = SEARCH_UIDSET;
	p_array_init(&args->args->value.seqset, args->pool, 16);
	if (imap_seq_set_parse(uidset, &args->args->value.seqset) < 0) {
		*error_r = "Invalid uidset";
		mail_search_args_unref(&args);
		return -1;
	}

	*args_r = args;
	return 0;
}

int imap_search_get_seqset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_args **search_args_r)
{
	int ret;

	ret = imap_search_get_anyset(cmd, set, uid, search_args_r);
	if (ret > 0) {
		mail_search_args_init(*search_args_r,
				      cmd->client->mailbox, TRUE,
				      &cmd->client->search_saved_uidset);
	}
	return ret;
}

static int imap_search_get_searchres(struct client_command_context *cmd,
				     struct mail_search_args **search_args_r)
{
	struct mail_search_args *search_args;

	if (client_handle_search_save_ambiguity(cmd))
		return 0;

	search_args = mail_search_build_init();
	search_args->args = p_new(search_args->pool, struct mail_search_arg, 1);
	if (array_is_created(&cmd->client->search_saved_uidset)) {
		search_args->args->type = SEARCH_UIDSET;
		p_array_init(&search_args->args->value.seqset,
			     search_args->pool,
			     array_count(&cmd->client->search_saved_uidset));
		array_append_array(&search_args->args->value.seqset,
				   &cmd->client->search_saved_uidset);
	} else {
		/* $ not set yet, match nothing */
		search_args->args->type = SEARCH_ALL;
		search_args->args->match_not = TRUE;
	}
	*search_args_r = search_args;
	return 1;
}

int imap_search_get_anyset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_args **search_args_r)
{
	const char *client_error = NULL;
	int ret;

	if (strcmp(set, "$") == 0) {
		/* SEARCHRES extension: replace $ with the last saved
		   search result */
		return imap_search_get_searchres(cmd, search_args_r);
	}
	if (!uid) {
		ret = imap_search_get_msgset_arg(cmd, set, search_args_r,
						 &client_error);
	} else {
		ret = imap_search_get_uidset_arg(set, search_args_r,
						 &client_error);
	}
	if (ret < 0) {
		client_send_command_error(cmd, client_error);
		return -1;
	}
	return 1;
}

void imap_search_add_changed_since(struct mail_search_args *search_args,
				   uint64_t modseq)
{
	struct mail_search_arg *search_arg;

	search_arg = p_new(search_args->pool, struct mail_search_arg, 1);
	search_arg->type = SEARCH_MODSEQ;
	search_arg->value.modseq =
		p_new(search_args->pool, struct mail_search_modseq, 1);
	search_arg->value.modseq->modseq = modseq + 1;

	search_arg->next = search_args->args->next;
	search_args->args->next = search_arg;
}
