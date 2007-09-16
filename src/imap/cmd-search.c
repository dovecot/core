/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ostream.h"
#include "str.h"
#include "commands.h"
#include "imap-search.h"

#define OUTBUF_SIZE 65536

struct imap_search_context {
        struct mailbox_transaction_context *trans;
        struct mail_search_context *search_ctx;
	struct mail *mail;

	struct timeout *to;
	string_t *output_buf;

	unsigned int output_sent:1;
};

static struct imap_search_context *
imap_search_init(struct client_command_context *cmd, const char *charset,
		 struct mail_search_arg *sargs)
{
	struct imap_search_context *ctx;

	ctx = p_new(cmd->pool, struct imap_search_context, 1);
	ctx->trans = mailbox_transaction_begin(cmd->client->mailbox, 0);
	ctx->search_ctx = mailbox_search_init(ctx->trans, charset, sargs, NULL);
	ctx->mail = mail_alloc(ctx->trans, 0, NULL);

	ctx->output_buf = str_new(default_pool, OUTBUF_SIZE);
	str_append(ctx->output_buf, "* SEARCH");
	return ctx;
}

static int imap_search_deinit(struct client_command_context *cmd,
			      struct imap_search_context *ctx)
{
	int ret;

	mail_free(&ctx->mail);
	ret = mailbox_search_deinit(&ctx->search_ctx);

	if (mailbox_transaction_commit(&ctx->trans, 0) < 0)
		ret = -1;

	if (ctx->output_sent || (ret == 0 && !cmd->cancel)) {
		str_append(ctx->output_buf, "\r\n");
		o_stream_send(cmd->client->output,
			      str_data(ctx->output_buf),
			      str_len(ctx->output_buf));
	}
	if (ctx->to != NULL)
		timeout_remove(&ctx->to);
	str_free(&ctx->output_buf);

	cmd->context = NULL;
	return ret;
}

static bool cmd_search_more(struct client_command_context *cmd)
{
	struct imap_search_context *ctx = cmd->context;
	bool tryagain;
	int ret;

	if (cmd->cancel) {
		(void)imap_search_deinit(cmd, ctx);
		return TRUE;
	}

	while ((ret = mailbox_search_next_nonblock(ctx->search_ctx, ctx->mail,
						   &tryagain)) > 0) {
		if (str_len(ctx->output_buf) >= OUTBUF_SIZE - MAX_INT_STRLEN) {
			/* flush. this also causes us to lock the output. */
			cmd->client->output_lock = cmd;
			o_stream_send(cmd->client->output,
				      str_data(ctx->output_buf),
				      str_len(ctx->output_buf));
			str_truncate(ctx->output_buf, 0);
			ctx->output_sent = TRUE;
		}

		str_printfa(ctx->output_buf, " %u",
			    cmd->uid ? ctx->mail->uid : ctx->mail->seq);
	}
	if (tryagain)
		return FALSE;

	if (imap_search_deinit(cmd, ctx) < 0)
		ret = -1;

	if (ret < 0) {
		client_send_storage_error(cmd,
			mailbox_get_storage(cmd->client->mailbox));
		return TRUE;
	} else {
		return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
				(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
				0, "OK Search completed.");
	}
}

static void cmd_search_more_callback(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	bool finished;

	o_stream_cork(client->output);
	finished = cmd_search_more(cmd);
	o_stream_uncork(client->output);

	if (finished) {
		client_command_free(cmd);
		client_continue_pending_input(client);
	} else {
		if (cmd->output_pending)
			o_stream_set_flush_pending(client->output, TRUE);
	}
}

bool cmd_search(struct client_command_context *cmd)
{
	struct imap_search_context *ctx;
	struct mail_search_arg *sargs;
	const struct imap_arg *args;
	int args_count;
	const char *error, *charset;

	args_count = imap_parser_read_args(cmd->parser, 0, 0, &args);
	if (args_count < 1) {
		if (args_count == -2)
			return FALSE;

		client_send_command_error(cmd, args_count < 0 ? NULL :
					  "Missing SEARCH arguments.");
		return TRUE;
	}
	cmd->client->input_lock = NULL;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (args->type == IMAP_ARG_ATOM &&
	    strcasecmp(IMAP_ARG_STR_NONULL(args), "CHARSET") == 0) {
		/* CHARSET specified */
		args++;
		if (args->type != IMAP_ARG_ATOM &&
		    args->type != IMAP_ARG_STRING) {
			client_send_command_error(cmd,
						  "Invalid charset argument.");
			return TRUE;
		}

		charset = IMAP_ARG_STR(args);
		args++;
	} else {
		charset = "UTF-8";
	}

	sargs = imap_search_args_build(cmd->pool, cmd->client->mailbox,
				       args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(cmd, t_strconcat("BAD ", error, NULL));
		return TRUE;
	}

	ctx = imap_search_init(cmd, charset, sargs);
	cmd->func = cmd_search_more;
	cmd->context = ctx;

	if (cmd_search_more(cmd))
		return TRUE;

	/* we could have moved onto syncing by now */
	if (cmd->func == cmd_search_more)
		ctx->to = timeout_add(0, cmd_search_more_callback, cmd);
	return FALSE;
}
