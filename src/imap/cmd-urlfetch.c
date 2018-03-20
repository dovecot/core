/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "strfuncs.h"
#include "str.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "istream-sized.h"
#include "ostream.h"
#include "imap-url.h"
#include "imap-quote.h"
#include "imap-common.h"
#include "imap-commands.h"
#include "imap-urlauth.h"
#include "imap-urlauth-fetch.h"

struct cmd_urlfetch_context {
	struct imap_urlauth_fetch *ufetch;
	struct istream *input;

	bool failed:1;
	bool finished:1;
	bool extended:1;
	bool in_io_handler:1;
};

struct cmd_urlfetch_url {
	const char *url;
	
	enum imap_urlauth_fetch_flags flags;
};

static void cmd_urlfetch_finish(struct client_command_context *cmd)
{
	struct cmd_urlfetch_context *ctx =
		(struct cmd_urlfetch_context *)cmd->context;

	if (ctx->finished)
		return;
	ctx->finished = TRUE;

	i_stream_unref(&ctx->input);
	if (ctx->ufetch != NULL)
		imap_urlauth_fetch_deinit(&ctx->ufetch);

	if (ctx->failed) {
		if (cmd->client->output_cmd_lock == cmd) {
			/* failed in the middle of a literal.
			   we need to disconnect. */
			cmd->client->output_cmd_lock = NULL;
			client_disconnect(cmd->client, "URLFETCH failed");
		} else {
			client_send_internal_error(cmd);
		}
		return;
	}

	client_send_tagline(cmd, "OK URLFETCH completed.");
}

static bool cmd_urlfetch_cancel(struct client_command_context *cmd)
{
	struct cmd_urlfetch_context *ctx =
		(struct cmd_urlfetch_context *)cmd->context;

	if (!cmd->cancel)
		return FALSE;

	if (ctx->ufetch != NULL) {
		e_debug(cmd->client->event,
			"URLFETCH: Canceling command; "
			"aborting URLAUTH fetch requests prematurely");
		imap_urlauth_fetch_deinit(&ctx->ufetch);
	}
	return TRUE;
}

static int cmd_urlfetch_transfer_literal(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_urlfetch_context *ctx =
		(struct cmd_urlfetch_context *)cmd->context;
	enum ostream_send_istream_result res;
	int ret;

	/* are we in the middle of an urlfetch literal? */
	if (ctx->input == NULL)
		return 1;

	/* flush output to client if buffer is filled above optimum */
	if (o_stream_get_buffer_used_size(client->output) >=
	    CLIENT_OUTPUT_OPTIMAL_SIZE) {
		if ((ret = o_stream_flush(client->output)) <= 0)
			return ret;
	}

	/* transfer literal to client */
	o_stream_set_max_buffer_size(client->output, 0);
	res = o_stream_send_istream(client->output, ctx->input);
	o_stream_set_max_buffer_size(client->output, (size_t)-1);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		i_stream_unref(&ctx->input);
		return 1;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_error("read(%s) failed: %s (URLFETCH)",
			i_stream_get_name(ctx->input),
			i_stream_get_error(ctx->input));
		client_disconnect(client, "URLFETCH failed");
		return -1;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		/* client disconnected */
		return -1;
	}
	i_unreached();
}

static bool cmd_urlfetch_continue(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_urlfetch_context *ctx =
		(struct cmd_urlfetch_context *)cmd->context;
	bool urls_pending;
	int ret = 1;

	if (cmd->cancel)
		return cmd_urlfetch_cancel(cmd);

	i_assert(client->output_cmd_lock == NULL ||
		 client->output_cmd_lock == cmd);

	/* finish a pending literal transfer */
	ret = cmd_urlfetch_transfer_literal(cmd);
	if (ret < 0) {
		ctx->failed = TRUE;
		cmd_urlfetch_finish(cmd);
		return TRUE;
	}
	if (ret == 0) {
		/* not finished; apparently output blocked again */
		return FALSE;
	}

	if (ctx->extended)
		client_send_line(client, ")");
	else
		client_send_line(client, "");
	client->output_cmd_lock = NULL;

	ctx->in_io_handler = TRUE;
	urls_pending = imap_urlauth_fetch_continue(ctx->ufetch);
	ctx->in_io_handler = FALSE;

	if (urls_pending) {
		/* waiting for imap urlauth service */
		cmd->state = CLIENT_COMMAND_STATE_WAIT_EXTERNAL;
		cmd->func = cmd_urlfetch_cancel;

		/* retrieve next url */
		return FALSE;
	}

	/* finished */
	cmd_urlfetch_finish(cmd);
	return TRUE;
}

static int cmd_urlfetch_url_success(struct client_command_context *cmd,
				   struct imap_urlauth_fetch_reply *reply)
{
	struct cmd_urlfetch_context *ctx = cmd->context;
	string_t *response = t_str_new(256);
	int ret;

	str_append(response, "* URLFETCH ");
	imap_append_astring(response, reply->url);

	if ((reply->flags & IMAP_URLAUTH_FETCH_FLAG_EXTENDED) == 0) {
		/* simple */
		ctx->extended = FALSE;

		str_printfa(response, " {%"PRIuUOFF_T"}", reply->size);
		client_send_line(cmd->client, str_c(response));
		i_assert(reply->size == 0 || reply->input != NULL);
	} else {
		bool metadata = FALSE;

		/* extended */
		ctx->extended = TRUE;

		str_append(response, " (");
		if ((reply->flags & IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE) != 0 &&
		    reply->bodypartstruct != NULL) {
			str_append(response, "BODYPARTSTRUCTURE (");
			str_append(response, reply->bodypartstruct);
			str_append_c(response, ')');
			metadata = TRUE;
		}
		if ((reply->flags & IMAP_URLAUTH_FETCH_FLAG_BODY) != 0 ||
		    (reply->flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0) {
			if (metadata)
				str_append_c(response, ' ');
			if ((reply->flags & IMAP_URLAUTH_FETCH_FLAG_BODY) != 0) {
				str_append(response, "BODY ");
			} else {
				str_append(response, "BINARY ");
				if (reply->binary_has_nuls)
					str_append_c(response, '~');
			}
			str_printfa(response, "{%"PRIuUOFF_T"}", reply->size);
			i_assert(reply->size == 0 || reply->input != NULL);
		} else {
			str_append_c(response, ')');
			ctx->extended = FALSE;
		}

		client_send_line(cmd->client, str_c(response));
	}

	if (reply->input != NULL) {
		ctx->input = i_stream_create_sized(reply->input, reply->size);

		ret = cmd_urlfetch_transfer_literal(cmd);
		if (ret < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		if (ret == 0) {
			/* not finished; apparently output blocked */
			cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;
			cmd->func = cmd_urlfetch_continue;
			cmd->client->output_cmd_lock = cmd;
			return 0;
		}

		if (ctx->extended)
			client_send_line(cmd->client, ")");
		else
			client_send_line(cmd->client, "");
	}
	return 1;
}

static int
cmd_urlfetch_url_callback(struct imap_urlauth_fetch_reply *reply,
			  bool last, void *context)
{
	struct client_command_context *cmd = context;
	struct client *client = cmd->client;
	struct cmd_urlfetch_context *ctx = cmd->context;
	bool in_io_handler = ctx->in_io_handler;
	int ret;

	if (!in_io_handler)
		o_stream_cork(client->output);
	if (reply == NULL) {
		/* fatal failure */
		ctx->failed = TRUE;
		ret = -1;
	} else if (reply->succeeded) {
		/* URL fetch succeeded */
		ret = cmd_urlfetch_url_success(cmd, reply);
	} else {
		/* URL fetch failed */
		string_t *response = t_str_new(128);

		str_append(response, "* URLFETCH ");
		imap_append_astring(response, reply->url);
		str_append(response, " NIL");
		client_send_line(client, str_c(response));
		if (reply->error != NULL) {
			client_send_line(client, t_strdup_printf(
				"* NO %s.", reply->error));
		}
		ret = 1;
	}

	if ((last && cmd->state == CLIENT_COMMAND_STATE_WAIT_EXTERNAL) ||
	    ret < 0) {
		cmd_urlfetch_finish(cmd);
		client_command_free(&cmd);
	}
	if (!in_io_handler)
		o_stream_uncork(client->output);
	return ret;
}

static int
cmd_urlfetch_parse_arg(struct client_command_context *cmd,
		       const struct imap_arg *arg,
		       struct cmd_urlfetch_url *ufurl_r)
{
	enum imap_urlauth_fetch_flags url_flags = 0;
	const struct imap_arg *params;
	const char *url_text;

	if (imap_arg_get_list(arg, &params))
		url_flags |= IMAP_URLAUTH_FETCH_FLAG_EXTENDED;
	else
		params = arg;

	/* read url */
	if (!imap_arg_get_astring(params++, &url_text)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return -1;
	}
	ufurl_r->url = t_strdup(url_text);
	if (url_flags == 0)
		return 0;

	while (!IMAP_ARG_IS_EOL(params)) {
		const char *fetch_param;

		if (!imap_arg_get_atom(params++, &fetch_param)) {
			client_send_command_error(cmd,
				"Invalid URL fetch parameter.");
			return -1;
		}

		if (strcasecmp(fetch_param, "BODY") == 0)
			url_flags |= IMAP_URLAUTH_FETCH_FLAG_BODY;
		else if (strcasecmp(fetch_param, "BINARY") == 0)
			url_flags |= IMAP_URLAUTH_FETCH_FLAG_BINARY;
		else if (strcasecmp(fetch_param, "BODYPARTSTRUCTURE") == 0)
			url_flags |= IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE;
		else {
			client_send_command_error(cmd,
				t_strdup_printf("Unknown URL fetch parameter: %s",
						fetch_param));
			return -1;
		}
	}

	if ((url_flags & IMAP_URLAUTH_FETCH_FLAG_BODY) != 0 &&
	    (url_flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0) {
		client_send_command_error(cmd,
			"URL cannot have both BODY and BINARY fetch parameters.");
		return -1;
	}

	if (url_flags == IMAP_URLAUTH_FETCH_FLAG_EXTENDED)
		url_flags |= IMAP_URLAUTH_FETCH_FLAG_BODY;
	ufurl_r->flags = url_flags;
	return 0;
}

bool cmd_urlfetch(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_urlfetch_context *ctx;
	ARRAY(struct cmd_urlfetch_url) urls;
	const struct cmd_urlfetch_url *url;
	const struct imap_arg *args;
	struct cmd_urlfetch_url *ufurl;

	if (client->urlauth_ctx == NULL) {
		client_send_command_error(cmd, "URLAUTH disabled.");
		return TRUE;
	}

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	
	t_array_init(&urls, 32);

	/* parse url arguments and group them per userid */
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		ufurl = array_append_space(&urls);
		if (cmd_urlfetch_parse_arg(cmd, args, ufurl) < 0)
			return TRUE;
	}
	cmd->context = ctx = p_new(cmd->pool, struct cmd_urlfetch_context, 1);
	cmd->func = cmd_urlfetch_cancel;
	cmd->state = CLIENT_COMMAND_STATE_WAIT_INPUT;

	ctx->ufetch = imap_urlauth_fetch_init(client->urlauth_ctx,
					      cmd_urlfetch_url_callback, cmd);

	ctx->in_io_handler = TRUE;
	array_foreach(&urls, url) {
		if (imap_urlauth_fetch_url(ctx->ufetch, url->url, url->flags) < 0) {
			/* fatal error */
			ctx->failed = TRUE;
			break;
		}
	}
	ctx->in_io_handler = FALSE;

	if ((ctx->failed || !imap_urlauth_fetch_is_pending(ctx->ufetch))
		&& cmd->client->output_cmd_lock != cmd) {
		/* finished */
		cmd_urlfetch_finish(cmd);
		return TRUE;
	}

	if (cmd->client->output_cmd_lock != cmd)
		cmd->state = CLIENT_COMMAND_STATE_WAIT_EXTERNAL;
	return FALSE;	
}
