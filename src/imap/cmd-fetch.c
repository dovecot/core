/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ostream.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "imap-fetch.h"
#include "imap-search-args.h"
#include "mail-search.h"


static const char *all_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", NULL
};
static const char *fast_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", NULL
};
static const char *full_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY", NULL
};

static bool
imap_fetch_cmd_init_handler(struct imap_fetch_context *ctx,
			    struct client_command_context *cmd,
			    const char *name, const struct imap_arg **args)
{
	struct imap_fetch_init_context init_ctx;

	i_zero(&init_ctx);
	init_ctx.fetch_ctx = ctx;
	init_ctx.pool = ctx->ctx_pool;
	init_ctx.name = name;
	init_ctx.args = *args;

	if (!imap_fetch_init_handler(&init_ctx)) {
		i_assert(init_ctx.error != NULL);
		client_send_command_error(cmd, init_ctx.error);
		return FALSE;
	}
	*args = init_ctx.args;
	return TRUE;
}

static bool
fetch_parse_args(struct imap_fetch_context *ctx,
		 struct client_command_context *cmd,
		 const struct imap_arg *arg, const struct imap_arg **next_arg_r)
{
	const char *str, *const *macro;

	if (cmd->uid) {
		if (!imap_fetch_cmd_init_handler(ctx, cmd, "UID", &arg))
			return FALSE;
	}
	if (imap_arg_get_atom(arg, &str)) {
		str = t_str_ucase(str);
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
			if (!imap_fetch_cmd_init_handler(ctx, cmd, str, &arg))
				return FALSE;
		}
		if (macro != NULL) {
			while (*macro != NULL) {
				if (!imap_fetch_cmd_init_handler(ctx, cmd, *macro, &arg))
					return FALSE;
				macro++;
			}
		}
		*next_arg_r = arg;
	} else {
		*next_arg_r = arg + 1;
		arg = imap_arg_as_list(arg);
		if (IMAP_ARG_IS_EOL(arg)) {
			client_send_command_error(cmd,
						  "FETCH list is empty.");
			return FALSE;
		}
		while (imap_arg_get_atom(arg, &str)) {
			str = t_str_ucase(str);
			arg++;
			if (!imap_fetch_cmd_init_handler(ctx, cmd, str, &arg))
				return FALSE;
		}
		if (!IMAP_ARG_IS_EOL(arg)) {
			client_send_command_error(cmd,
				"FETCH list contains non-atoms.");
			return FALSE;
		}
	}
	return TRUE;
}

static bool
fetch_parse_modifier(struct imap_fetch_context *ctx,
		     struct client_command_context *cmd,
		     struct mail_search_args *search_args,
		     const char *name, const struct imap_arg **args,
		     bool *send_vanished)
{
	const char *str;
	uint64_t modseq;

	if (strcmp(name, "CHANGEDSINCE") == 0) {
		if (cmd->client->nonpermanent_modseqs) {
			client_send_command_error(cmd,
				"FETCH CHANGEDSINCE can't be used with non-permanent modseqs");
			return FALSE;
		}
		if (!imap_arg_get_atom(*args, &str) ||
		    str_to_uint64(str, &modseq) < 0) {
			client_send_command_error(cmd,
				"Invalid CHANGEDSINCE modseq.");
			return FALSE;
		}
		*args += 1;
		imap_search_add_changed_since(search_args, modseq);
		imap_fetch_init_nofail_handler(ctx, imap_fetch_modseq_init);
		return TRUE;
	}
	if (strcmp(name, "VANISHED") == 0 && cmd->uid) {
		if (!client_has_enabled(ctx->client, imap_feature_qresync)) {
			client_send_command_error(cmd, "QRESYNC not enabled");
			return FALSE;
		}
		*send_vanished = TRUE;
		return TRUE;
	}

	client_send_command_error(cmd, "Unknown FETCH modifier");
	return FALSE;
}

static bool
fetch_parse_modifiers(struct imap_fetch_context *ctx,
		      struct client_command_context *cmd,
		      struct mail_search_args *search_args,
		      const struct imap_arg *args, bool *send_vanished_r)
{
	const char *name;

	*send_vanished_r = FALSE;

	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &name)) {
			client_send_command_error(cmd,
				"FETCH modifiers contain non-atoms.");
			return FALSE;
		}
		args++;
		if (!fetch_parse_modifier(ctx, cmd, search_args,
					  t_str_ucase(name),
					  &args, send_vanished_r))
			return FALSE;
	}
	if (*send_vanished_r &&
	    (search_args->args->next == NULL ||
	     search_args->args->next->type != SEARCH_MODSEQ)) {
		client_send_command_error(cmd,
			"VANISHED used without CHANGEDSINCE");
		return FALSE;
	}
	return TRUE;
}

static bool cmd_fetch_finished(struct client_command_context *cmd ATTR_UNUSED)
{
	return TRUE;
}

static bool imap_fetch_is_failed_retry(struct imap_fetch_context *ctx)
{
	if (!array_is_created(&ctx->client->fetch_failed_uids) ||
	    !array_is_created(&ctx->fetch_failed_uids))
		return FALSE;
	return seq_range_array_have_common(&ctx->client->fetch_failed_uids,
					   &ctx->fetch_failed_uids);

}

static void imap_fetch_add_failed_uids(struct imap_fetch_context *ctx)
{
	if (!array_is_created(&ctx->fetch_failed_uids))
		return;
	if (!array_is_created(&ctx->client->fetch_failed_uids)) {
		p_array_init(&ctx->client->fetch_failed_uids, ctx->client->pool,
			     array_count(&ctx->fetch_failed_uids));
	}
	seq_range_array_merge(&ctx->client->fetch_failed_uids,
			      &ctx->fetch_failed_uids);
}

static bool cmd_fetch_finish(struct imap_fetch_context *ctx,
			     struct client_command_context *cmd)
{
	static const char *ok_message = "OK Fetch completed.";
	const char *tagged_reply = ok_message;
	enum mail_error error;
	bool seen_flags_changed = ctx->state.seen_flags_changed;

	if (ctx->state.skipped_expunged_msgs) {
		tagged_reply = "OK ["IMAP_RESP_CODE_EXPUNGEISSUED"] "
			"Some messages were already expunged.";
	}

	if (imap_fetch_end(ctx) < 0) {
		const char *errstr;

		if (cmd->client->output->closed) {
			/* If we're canceling we need to finish this command
			   or we'll assert crash. But normally we want to
			   return FALSE so that the disconnect message logs
			   about this fetch command and that these latest
			   output bytes are included in it (which wouldn't
			   happen if we called client_disconnect() here
			   directly). */
			cmd->func = cmd_fetch_finished;
			imap_fetch_free(&ctx);
			return cmd->cancel;
		}

		if (ctx->error == MAIL_ERROR_NONE)
			errstr = mailbox_get_last_error(cmd->client->mailbox, &error);
		else {
			errstr = ctx->errstr;
			error = ctx->error;
		}
		if (error == MAIL_ERROR_CONVERSION) {
			/* BINARY found unsupported Content-Transfer-Encoding */
			tagged_reply = t_strdup_printf(
				"NO ["IMAP_RESP_CODE_UNKNOWN_CTE"] %s", errstr);
		} else if (error == MAIL_ERROR_INVALIDDATA) {
			/* Content was invalid */
			tagged_reply = t_strdup_printf(
				"NO ["IMAP_RESP_CODE_PARSE"] %s", errstr);
		} else if (cmd->client->set->parsed_fetch_failure != IMAP_CLIENT_FETCH_FAILURE_NO_AFTER ||
			   imap_fetch_is_failed_retry(ctx)) {
			/* By default we never want to reply NO to FETCH
			   requests, because many IMAP clients become confused
			   about what they should on NO. A disconnection causes
			   less confusion. */
			client_disconnect_with_error(cmd->client,
				t_strconcat("FETCH failed: ", errstr, NULL));
			imap_fetch_free(&ctx);
			return TRUE;
		} else {
			/* Use a tagged NO to FETCH failure, but only if client
			   hasn't repeated the FETCH to the same email (so that
			   we avoid infinitely retries from client.) */
			imap_fetch_add_failed_uids(ctx);
			tagged_reply = t_strdup_printf(
				"NO ["IMAP_RESP_CODE_SERVERBUG"] %s", errstr);
		}
	}
	imap_fetch_free(&ctx);

	return cmd_sync(cmd,
			(seen_flags_changed ? 0 : MAILBOX_SYNC_FLAG_FAST) |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES), 0,
			tagged_reply);
}

static bool cmd_fetch_continue(struct client_command_context *cmd)
{
        struct imap_fetch_context *ctx = cmd->context;

	if (imap_fetch_more(ctx, cmd) == 0) {
		/* unfinished */
		return FALSE;
	}
	return cmd_fetch_finish(ctx, cmd);
}

bool cmd_fetch(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct imap_fetch_context *ctx;
	const struct imap_arg *args, *next_arg, *list_arg;
	struct mail_search_args *search_args;
	struct imap_fetch_qresync_args qresync_args;
	const char *messageset;
	bool send_vanished = FALSE;
	int ret;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* <messageset> <field(s)> [(modifiers)] */
	if (!imap_arg_get_atom(&args[0], &messageset) ||
	    (args[1].type != IMAP_ARG_LIST && args[1].type != IMAP_ARG_ATOM) ||
	    (!IMAP_ARG_IS_EOL(&args[2]) && args[2].type != IMAP_ARG_LIST)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	/* UID FETCH VANISHED needs the uidset, so convert it to
	   sequence set later */
	ret = imap_search_get_anyset(cmd, messageset, cmd->uid, &search_args);
	if (ret <= 0)
		return ret < 0;

	ctx = imap_fetch_alloc(client, cmd->pool,
			       imap_client_command_get_reason(cmd));

	if (!fetch_parse_args(ctx, cmd, &args[1], &next_arg) ||
	    (imap_arg_get_list(next_arg, &list_arg) &&
	     !fetch_parse_modifiers(ctx, cmd, search_args, list_arg,
				    &send_vanished))) {
		imap_fetch_free(&ctx);
		mail_search_args_unref(&search_args);
		return TRUE;
	}

	if (send_vanished) {
		i_zero(&qresync_args);
		if (imap_fetch_send_vanished(client, client->mailbox,
					     search_args, &qresync_args) < 0) {
			mail_search_args_unref(&search_args);
			return cmd_fetch_finish(ctx, cmd);
		}
	}

	imap_fetch_begin(ctx, client->mailbox, search_args);
	mail_search_args_unref(&search_args);

	if (imap_fetch_more(ctx, cmd) == 0) {
		/* unfinished */
		cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;

		cmd->func = cmd_fetch_continue;
		cmd->context = ctx;
		return FALSE;
	}
	return cmd_fetch_finish(ctx, cmd);
}
