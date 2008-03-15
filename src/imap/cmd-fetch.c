/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ostream.h"
#include "commands.h"
#include "imap-fetch.h"
#include "imap-search.h"
#include "mail-search.h"

#include <stdlib.h>

const char *all_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", NULL
};
const char *fast_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", NULL
};
const char *full_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY", NULL
};

static bool
fetch_parse_args(struct imap_fetch_context *ctx, const struct imap_arg *arg)
{
	const char *str, *const *macro;

	if (ctx->cmd->uid) {
		if (!imap_fetch_init_handler(ctx, "UID", &arg))
			return FALSE;
	}
	if (arg->type == IMAP_ARG_ATOM) {
		str = t_str_ucase(IMAP_ARG_STR(arg));
		arg++;

		/* handle macros first */
		if (strcmp(str, "ALL") == 0)
			macro = all_macro;
		else if (strcmp(str, "FAST") == 0)
			macro = fast_macro;
		else if (strcmp(str, "FULL") == 0)
			macro = full_macro;
		else {
			macro = NULL;
			if (!imap_fetch_init_handler(ctx, str, &arg))
				return FALSE;
		}
		if (macro != NULL) {
			while (*macro != NULL) {
				if (!imap_fetch_init_handler(ctx, *macro, &arg))
					return FALSE;
				macro++;
			}
		}
	} else {
		arg = IMAP_ARG_LIST_ARGS(arg);
		while (arg->type == IMAP_ARG_ATOM) {
			str = t_str_ucase(IMAP_ARG_STR(arg));
			arg++;
			if (!imap_fetch_init_handler(ctx, str, &arg))
				return FALSE;
		}
		if (arg->type != IMAP_ARG_EOL) {
			client_send_command_error(ctx->cmd,
				"FETCH list contains non-atoms.");
			return FALSE;
		}
	}
	return TRUE;
}

static bool
fetch_parse_modifier(struct imap_fetch_context *ctx,
		     const char *name, const struct imap_arg **args)
{
	unsigned long long num;

	if (strcmp(name, "CHANGEDSINCE") == 0) {
		if ((*args)->type != IMAP_ARG_ATOM) {
			client_send_command_error(ctx->cmd,
				"Invalid CHANGEDSINCE modseq.");
			return FALSE;
		}
		num = strtoull(imap_arg_string(*args), NULL, 10);
		*args += 1;
		return imap_fetch_add_unchanged_since(ctx, num);
	}
	if (strcmp(name, "VANISHED") == 0 && ctx->cmd->uid) {
		if ((ctx->client->enabled_features &
		     MAILBOX_FEATURE_QRESYNC) == 0) {
			client_send_command_error(ctx->cmd,
						  "QRESYNC not enabled");
			return FALSE;
		}
		ctx->send_vanished = TRUE;
		return TRUE;
	}

	client_send_command_error(ctx->cmd, "Unknown FETCH modifier");
	return FALSE;
}

static bool
fetch_parse_modifiers(struct imap_fetch_context *ctx,
		      const struct imap_arg *args)
{
	const char *name;

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(ctx->cmd,
				"FETCH modifiers contain non-atoms.");
			return FALSE;
		}
		name = t_str_ucase(IMAP_ARG_STR(args));
		args++;
		if (!fetch_parse_modifier(ctx, name, &args))
			return FALSE;
	}
	if (ctx->send_vanished &&
	    (ctx->search_args->next == NULL ||
	     ctx->search_args->next->type != SEARCH_MODSEQ)) {
		client_send_command_error(ctx->cmd,
			"VANISHED used without CHANGEDSINCE");
		return FALSE;
	}
	return TRUE;
}

static bool cmd_fetch_finish(struct imap_fetch_context *ctx)
{
	struct client_command_context *cmd = ctx->cmd;
	static const char *ok_message = "OK Fetch completed.";

	if (imap_fetch_deinit(ctx) < 0)
		ctx->failed = TRUE;

	if (ctx->failed) {
		struct mail_storage *storage;
		const char *error_string;
		enum mail_error error;

		if (ctx->client->output->closed) {
			client_disconnect(cmd->client, "Disconnected");
			return TRUE;
		}

                storage = mailbox_get_storage(cmd->client->mailbox);
		error_string = mail_storage_get_last_error(storage, &error);

		/* We never want to reply NO to FETCH requests,
		   BYE is preferrable (see imap-ml for reasons). */
		client_disconnect_with_error(cmd->client, error_string);
		return TRUE;
	}

	return cmd_sync(cmd,
			(ctx->seen_flags_changed ? 0 : MAILBOX_SYNC_FLAG_FAST) |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES), 0,
			ok_message);
}

static bool cmd_fetch_continue(struct client_command_context *cmd)
{
        struct imap_fetch_context *ctx = cmd->context;

	if (imap_fetch_more(ctx) == 0) {
		/* unfinished */
		return FALSE;
	}
	return cmd_fetch_finish(ctx);
}

bool cmd_fetch(struct client_command_context *cmd)
{
	struct imap_fetch_context *ctx;
	const struct imap_arg *args;
	struct mail_search_arg *search_arg;
	const char *messageset;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* <messageset> <field(s)> [(CHANGEDSINCE <modseq>)] */
	messageset = imap_arg_string(&args[0]);
	if (messageset == NULL ||
	    (args[1].type != IMAP_ARG_LIST && args[1].type != IMAP_ARG_ATOM) ||
	    (args[2].type != IMAP_ARG_EOL && args[2].type != IMAP_ARG_LIST)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	search_arg = imap_search_get_anyset(cmd, messageset, cmd->uid);
	if (search_arg == NULL)
		return TRUE;

	ctx = imap_fetch_init(cmd, cmd->client->mailbox);
	if (ctx == NULL)
		return TRUE;
	ctx->search_args = search_arg;

	if (!fetch_parse_args(ctx, &args[1]) ||
	    (args[2].type == IMAP_ARG_LIST &&
	     !fetch_parse_modifiers(ctx, IMAP_ARG_LIST_ARGS(&args[2])))) {
		imap_fetch_deinit(ctx);
		return TRUE;
	}

	if (imap_fetch_begin(ctx) == 0) {
		if (imap_fetch_more(ctx) == 0) {
			/* unfinished */
			cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;

			cmd->func = cmd_fetch_continue;
			cmd->context = ctx;
			return FALSE;
		}
	}
	return cmd_fetch_finish(ctx);
}
