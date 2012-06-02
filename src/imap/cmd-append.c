/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-chain.h"
#include "ostream.h"
#include "str.h"
#include "imap-parser.h"
#include "imap-date.h"
#include "imap-util.h"
#include "imap-commands.h"
#include "imap-msgpart-url.h"

#include <sys/time.h>

/* Don't allow internaldates to be too far in the future. At least with Maildir
   they can cause problems with incremental backups since internaldate is
   stored in file's mtime. But perhaps there are also some other reasons why
   it might not be wanted. */
#define INTERNALDATE_MAX_FUTURE_SECS (2*3600)

struct cmd_append_context {
	struct client *client;
        struct client_command_context *cmd;
	struct mail_storage *storage;
	struct mailbox *box;
        struct mailbox_transaction_context *t;
	time_t started;

	struct istream_chain *catchain;
	uoff_t cat_msg_size;

	struct istream *input;
	struct istream *litinput;
	uoff_t literal_size;

	struct imap_parser *save_parser;
	struct mail_save_context *save_ctx;
	unsigned int count;

	unsigned int message_input:1;
	unsigned int catenate:1;
	unsigned int failed:1;
};

static void cmd_append_finish(struct cmd_append_context *ctx);
static bool cmd_append_continue_message(struct client_command_context *cmd);
static bool cmd_append_continue_parsing(struct client_command_context *cmd);

static const char *get_disconnect_reason(struct cmd_append_context *ctx)
{
	string_t *str = t_str_new(128);
	unsigned int secs = ioloop_time - ctx->started;

	str_printfa(str, "Disconnected in APPEND (%u msgs, %u secs",
		    ctx->count, secs);
	if (ctx->input != NULL) {
		str_printfa(str, ", %"PRIuUOFF_T"/%"PRIuUOFF_T" bytes",
			    ctx->input->v_offset, ctx->literal_size);
	}
	str_append_c(str, ')');
	return str_c(str);
}

static void client_input_append(struct client_command_context *cmd)
{
	struct cmd_append_context *ctx = cmd->context;
	struct client *client = cmd->client;
	const char *reason;
	bool finished;

	i_assert(!client->destroyed);

	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		reason = get_disconnect_reason(ctx);
		cmd_append_finish(cmd->context);
		/* Reset command so that client_destroy() doesn't try to call
		   cmd_append_continue_message() anymore. */
		client_command_free(&cmd);
		client_destroy(client, reason);
		return;
	case -2:
		if (ctx->message_input) {
			/* message data, this is handled internally by
			   mailbox_save_continue() */
			break;
		}
		cmd_append_finish(cmd->context);

		/* parameter word is longer than max. input buffer size.
		   this is most likely an error, so skip the new data
		   until newline is found. */
		client->input_skip_line = TRUE;

		client_send_command_error(cmd, "Too long argument.");
		cmd->param_error = TRUE;
		client_command_free(&cmd);
		return;
	}

	o_stream_cork(client->output);
	finished = command_exec(cmd);
	if (!finished && cmd->state != CLIENT_COMMAND_STATE_DONE)
		(void)client_handle_unfinished_cmd(cmd);
	else
		client_command_free(&cmd);
	(void)cmd_sync_delayed(client);
	o_stream_uncork(client->output);

	if (client->disconnected)
		client_destroy(client, NULL);
	else
		client_continue_pending_input(client);
}

static void cmd_append_finish(struct cmd_append_context *ctx)
{
	imap_parser_unref(&ctx->save_parser);

	i_assert(ctx->client->input_lock == ctx->cmd);

	io_remove(&ctx->client->io);
	/* we must put back the original flush callback before beginning to
	   sync (the command is still unfinished at that point) */
	o_stream_set_flush_callback(ctx->client->output,
				    client_output, ctx->client);

	if (ctx->litinput != NULL)
		i_stream_unref(&ctx->litinput);
	if (ctx->input != NULL)
		i_stream_unref(&ctx->input);
	if (ctx->save_ctx != NULL)
		mailbox_save_cancel(&ctx->save_ctx);
	if (ctx->t != NULL)
		mailbox_transaction_rollback(&ctx->t);
	if (ctx->box != ctx->cmd->client->mailbox && ctx->box != NULL)
		mailbox_free(&ctx->box);
}

static bool cmd_append_continue_cancel(struct client_command_context *cmd)
{
	struct cmd_append_context *ctx = cmd->context;
	size_t size;

	if (cmd->cancel) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	(void)i_stream_read(ctx->input);
	(void)i_stream_get_data(ctx->input, &size);
	i_stream_skip(ctx->input, size);

	if (cmd->client->input->closed) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	if (ctx->litinput->v_offset == ctx->literal_size) {
		/* finished, but with MULTIAPPEND and LITERAL+ we may get
		   more messages. */
		i_stream_unref(&ctx->litinput);

		ctx->message_input = FALSE;
		imap_parser_reset(ctx->save_parser);
		cmd->func = cmd_append_continue_parsing;
		return cmd_append_continue_parsing(cmd);
	}

	return FALSE;
}

static bool cmd_append_cancel(struct cmd_append_context *ctx, bool nonsync)
{
	ctx->failed = TRUE;

	if (!nonsync) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	/* we have to read the nonsynced literal so we don't treat the message
	   data as commands. */
	ctx->input = i_stream_create_limit(ctx->client->input, ctx->literal_size);

	ctx->message_input = TRUE;
	ctx->cmd->func = cmd_append_continue_cancel;
	ctx->cmd->context = ctx;
	return cmd_append_continue_cancel(ctx->cmd);
}

static int
cmd_append_catenate(struct client_command_context *cmd,
		    const struct imap_arg *args, bool *nonsync_r)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	struct imap_msgpart_url *mpurl;
	const char *catpart, *error;
	uoff_t newsize;
	int ret;

	*nonsync_r = FALSE;

	/* Handle URLs until a TEXT literal is encountered */
	while (imap_arg_get_atom(args, &catpart)) {
		const char *caturl;

		if (strcasecmp(catpart, "URL") == 0 ) {
			/* URL <url> */ 
			args++;
			if (!imap_arg_get_astring(args, &caturl))
				break;
			if (ctx->failed)
				return -1;

			mpurl = imap_msgpart_url_parse(client->user, client->mailbox, caturl, &error);
			if (mpurl == NULL) {
				/* invalid url, abort */
				client_send_tagline(cmd,
					t_strdup_printf("NO [BADURL %s] %s.", caturl, error));
				return -1;
			}

			if (cmd->cancel) {
				imap_msgpart_url_free(&mpurl);
				cmd_append_finish(ctx);
				return 1;
			}

			/* catenate URL */
			if (ctx->save_ctx != NULL) {
				struct istream *input = NULL;
				uoff_t size;

				if (!imap_msgpart_url_read_part(mpurl, &input, &size, &error)) {
					/* invalid url, abort */
					client_send_tagline(cmd,
						t_strdup_printf("NO [BADURL %s] %s.", caturl, error));
					return -1;
				}

				newsize = ctx->cat_msg_size + size;
				if (newsize < ctx->cat_msg_size) {
					client_send_tagline(cmd,
						"NO [TOOBIG] Composed message grows too big.");
					imap_msgpart_url_free(&mpurl);
					return -1;
				}

				if (input != NULL) {
					ctx->cat_msg_size = newsize;
					i_stream_chain_append(ctx->catchain, input);

					while (!input->eof) {
						ret = i_stream_read(ctx->input);
						if (mailbox_save_continue(ctx->save_ctx) < 0) {
							/* we still have to finish reading the message
							   from client */
							mailbox_save_cancel(&ctx->save_ctx);
							break;
						}
						if (ret == -1 || ret == 0)
							break;
					}

					if (!input->eof) {
						client_send_tagline(cmd, t_strdup_printf(
							"NO [BADURL %s] Failed to read all data.", caturl));
						imap_msgpart_url_free(&mpurl);
						return -1;
					}
				}
			}
			imap_msgpart_url_free(&mpurl);
		} else if (strcasecmp(catpart, "TEXT") == 0) {
			/* TEXT <literal> */
			args++;
			if (!imap_arg_get_literal_size(args, &ctx->literal_size))
				break;

			*nonsync_r = args->type == IMAP_ARG_LITERAL_SIZE_NONSYNC;
			if (ctx->failed) {
				/* we failed earlier, make sure we just eat
				   nonsync-literal if it's given. */
				return -1;
			}

			newsize = ctx->cat_msg_size + ctx->literal_size;
			if (newsize < ctx->cat_msg_size) {
				client_send_tagline(cmd,
					"NO [TOOBIG] Composed message grows too big.");
				return -1;
			}

			/* save the mail */
			ctx->cat_msg_size = newsize;
			ctx->litinput = i_stream_create_limit(client->input, ctx->literal_size);
			i_stream_chain_append(ctx->catchain, ctx->litinput);
			return 1;
		} else {
			break;
		}
		args++;
	}

	if (IMAP_ARG_IS_EOL(args)) {
		/* ")" */
		return 0;
	}
	client_send_command_error(cmd, "Invalid arguments.");
	return -1;
}

static void cmd_append_finish_catenate(struct client_command_context *cmd)
{
	struct cmd_append_context *ctx = cmd->context;

	i_stream_chain_append(ctx->catchain, NULL);
	i_stream_unref(&ctx->input);
	ctx->input = NULL;
	ctx->catenate = FALSE;

	if (mailbox_save_finish(&ctx->save_ctx) < 0) {
		ctx->failed = TRUE;
		client_send_storage_error(cmd, ctx->storage);
	}
}

static bool cmd_append_continue_catenate(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	const struct imap_arg *args;
	const char *msg;
	bool fatal, nonsync = FALSE;
	int ret;

	if (cmd->cancel) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	ret = imap_parser_read_args(ctx->save_parser, 0,
				    IMAP_PARSE_FLAG_LITERAL_SIZE |
				    IMAP_PARSE_FLAG_INSIDE_LIST, &args);
	if (ret == -1) {
		if (!ctx->failed) {
			msg = imap_parser_get_error(ctx->save_parser, &fatal);
			if (fatal)
				client_disconnect_with_error(client, msg);
			else
				client_send_command_error(cmd, msg);
		}
		client->input_skip_line = TRUE;
		cmd_append_finish(ctx);
		return TRUE;
	}
	if (ret < 0) {
		/* need more data */
		return FALSE;
	}

	if ((ret = cmd_append_catenate(cmd, args, &nonsync)) < 0) {
		client->input_skip_line = TRUE;
		return cmd_append_cancel(ctx, nonsync);
	}

	if (ret == 0) {
		/* ")" */
		cmd_append_finish_catenate(cmd);

		/* last catenate part */
		imap_parser_reset(ctx->save_parser);
		cmd->func = cmd_append_continue_parsing;
		return cmd_append_continue_parsing(cmd);
	}

	/* TEXT <literal> */

	/* after literal comes CRLF, if we fail make sure we eat it away */
	client->input_skip_line = TRUE;

	if (!nonsync) {
		o_stream_send(client->output, "+ OK\r\n", 6);
		o_stream_flush(client->output);
		o_stream_uncork(client->output);
		o_stream_cork(client->output);
	}

	ctx->message_input = TRUE;
	cmd->func = cmd_append_continue_message;
	return cmd_append_continue_message(cmd);
}

static int
cmd_append_handle_args(struct client_command_context *cmd,
		       const struct imap_arg **args, bool *nonsync_r)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	const struct imap_arg *flags_list;
	const struct imap_arg *cat_list = NULL;
	enum mail_flags flags;
	const char *const *keywords_list;
	struct mail_keywords *keywords;
	const char *internal_date_str;
	time_t internal_date;
	int ret, timezone_offset;
	bool valid;

	/* [<flags>] */
	if (!imap_arg_get_list(*args, &flags_list))
		flags_list = NULL;
	else
		(*args)++;

	/* [<internal date>] */
	if ((*args)->type != IMAP_ARG_STRING)
		internal_date_str = NULL;
	else {
		internal_date_str = imap_arg_as_astring(*args);
		(*args)++;
	}

	valid = FALSE;
	*nonsync_r = FALSE;
	ctx->catenate = FALSE;
	if (imap_arg_atom_equals(*args, "CATENATE")) {
		(*args)++;
		if (imap_arg_get_list(*args, &cat_list)) {
			valid = TRUE;
			ctx->catenate = TRUE;
		}
	} else if (imap_arg_get_literal_size(*args, &ctx->literal_size)) {
		*nonsync_r = (*args)->type == IMAP_ARG_LITERAL_SIZE_NONSYNC;
		valid = TRUE;
	}

	if (!valid) {
		client->input_skip_line = TRUE;
		client_send_command_error(cmd, "Invalid arguments.");
		return -1;
	}

	if (ctx->failed) {
		/* we failed earlier, make sure we just eat nonsync-literal
		   if it's given. */
		return -1;
	}

	if (flags_list != NULL) {
		if (!client_parse_mail_flags(cmd, flags_list,
					     &flags, &keywords_list))
			return -1;
		if (keywords_list == NULL)
			keywords = NULL;
		else if (mailbox_keywords_create(ctx->box, keywords_list,
						 &keywords) < 0) {
			client_send_storage_error(cmd, ctx->storage);
			return -1;
		}
	} else {
		flags = 0;
		keywords = NULL;
	}

	if (internal_date_str == NULL) {
		/* no time given, default to now. */
		internal_date = (time_t)-1;
		timezone_offset = 0;
	} else if (!imap_parse_datetime(internal_date_str,
					&internal_date, &timezone_offset)) {
		client_send_tagline(cmd, "BAD Invalid internal date.");
		return -1;
	}

	if (internal_date != (time_t)-1 &&
	    internal_date > ioloop_time + INTERNALDATE_MAX_FUTURE_SECS) {
		/* the client specified a time in the future, set it to now. */
		internal_date = (time_t)-1;
		timezone_offset = 0;
	}

	if (cat_list != NULL) {
		ctx->cat_msg_size = 0;
		ctx->input = i_stream_create_chain(&ctx->catchain);
	} else {
		if (ctx->literal_size == 0) {
			/* no message data, abort */
			client_send_tagline(cmd, "NO Can't save a zero byte message.");
			return -1;
		}
		ctx->litinput = i_stream_create_limit(client->input, ctx->literal_size);
		ctx->input = ctx->litinput;
		i_stream_ref(ctx->input);
	}

	/* save the mail */
	ctx->save_ctx = mailbox_save_alloc(ctx->t);
	mailbox_save_set_flags(ctx->save_ctx, flags, keywords);
	mailbox_save_set_received_date(ctx->save_ctx,
				       internal_date, timezone_offset);
	ret = mailbox_save_begin(&ctx->save_ctx, ctx->input);
	ctx->count++;

	if (cat_list != NULL &&
	    (ret = cmd_append_catenate(cmd, cat_list, nonsync_r)) <= 0) {
		if (ret < 0)
			client->input_skip_line = TRUE;
		return ret;
	}

	if (keywords != NULL)
		mailbox_keywords_unref(&keywords);

	if (ret < 0) {
		/* save initialization failed */
		client_send_storage_error(cmd, ctx->storage);
		return -1;
	}
	return 1;
}

static bool cmd_append_finish_parsing(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	enum mailbox_sync_flags sync_flags;
	enum imap_sync_flags imap_flags;
	struct mail_transaction_commit_changes changes;
	unsigned int save_count;
	string_t *msg;
	int ret;

	/* eat away the trailing CRLF */
	client->input_skip_line = TRUE;

	if (ctx->failed) {
		/* we failed earlier, error message is sent */
		cmd_append_finish(ctx);
		return TRUE;
	}
	if (ctx->count == 0) {
		client_send_tagline(cmd, "BAD Missing message size.");
		cmd_append_finish(ctx);
		return TRUE;
	}

	ret = mailbox_transaction_commit_get_changes(&ctx->t, &changes);
	if (ret < 0) {
		client_send_storage_error(cmd, ctx->storage);
		cmd_append_finish(ctx);
		return TRUE;
	}

	msg = t_str_new(256);
	save_count = seq_range_count(&changes.saved_uids);
	if (save_count == 0) {
		/* not supported by backend (virtual) */
		str_append(msg, "OK Append completed.");
	} else {
		i_assert(ctx->count == save_count);
		str_printfa(msg, "OK [APPENDUID %u ",
			    changes.uid_validity);
		imap_write_seq_range(msg, &changes.saved_uids);
		str_append(msg, "] Append completed.");
	}
	pool_unref(&changes.pool);

	if (ctx->box == cmd->client->mailbox) {
		sync_flags = 0;
		imap_flags = IMAP_SYNC_FLAG_SAFE;
	} else {
		sync_flags = MAILBOX_SYNC_FLAG_FAST;
		imap_flags = 0;
	}

	cmd_append_finish(ctx);
	return cmd_sync(cmd, sync_flags, imap_flags, str_c(msg));
}

static bool cmd_append_continue_parsing(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	const struct imap_arg *args;
	const char *msg;
	bool fatal, nonsync;
	int ret;

	if (cmd->cancel) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	/* if error occurs, the CRLF is already read. */
	client->input_skip_line = FALSE;

	/* [<flags>] [<internal date>] <message literal> */
	ret = imap_parser_read_args(ctx->save_parser, 0,
				    IMAP_PARSE_FLAG_LITERAL_SIZE, &args);
	if (ret == -1) {
		if (!ctx->failed) {
			msg = imap_parser_get_error(ctx->save_parser, &fatal);
			if (fatal)
				client_disconnect_with_error(client, msg);
			else
				client_send_command_error(cmd, msg);
		}
		cmd_append_finish(ctx);
		return TRUE;
	}
	if (ret < 0) {
		/* need more data */
		return FALSE;
	}

	if (IMAP_ARG_IS_EOL(args)) {
		/* last message */
		return cmd_append_finish_parsing(cmd);
	}

	/* Handle multiple messages (IMAP URLs) while no literals are
	   encountered) */
	while ((ret = cmd_append_handle_args(cmd, &args, &nonsync)) == 0) {
		cmd_append_finish_catenate(cmd);

		/* Check for EOL, e.g.:
		   APPEND <box> ( URL <url> URL <url> URL <url> ) */
		args++;
		if (IMAP_ARG_IS_EOL(args)) {
			/* last message */
			return cmd_append_finish_parsing(cmd);
		}
	}

	if (ret < 0)
		return cmd_append_cancel(ctx, nonsync);

	if (!ctx->catenate) {
		/* after literal comes CRLF, if we fail make sure
		   we eat it away */
		client->input_skip_line = TRUE;

		if (!nonsync) {
			o_stream_send(client->output, "+ OK\r\n", 6);
			o_stream_flush(client->output);
			o_stream_uncork(client->output);
			o_stream_cork(client->output);
		}
		ctx->message_input = TRUE;
	}

	cmd->func = cmd_append_continue_message;
	return cmd_append_continue_message(cmd);
}

static bool cmd_append_continue_message(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	size_t size;
	int ret = 0;

	if (cmd->cancel) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	if (ctx->save_ctx != NULL) {
		while (ctx->litinput->v_offset != ctx->literal_size) {
			ret = i_stream_read(ctx->input);
			if (mailbox_save_continue(ctx->save_ctx) < 0) {
				/* we still have to finish reading the message
				   from client */
				mailbox_save_cancel(&ctx->save_ctx);
				break;
			}
			if (ret == -1 || ret == 0)
				break;
		}
	}

	if (ctx->save_ctx == NULL) {
		(void)i_stream_read(ctx->input);
		(void)i_stream_get_data(ctx->input, &size);
		i_stream_skip(ctx->input, size);
	}

	if (ctx->litinput->eof || client->input->closed) {
		bool all_written = ctx->litinput->v_offset == ctx->literal_size;

		/* finished */
		i_stream_unref(&ctx->litinput);

		if (ctx->save_ctx == NULL) {
			/* failed above */
			client_send_storage_error(cmd, ctx->storage);
			ctx->failed = TRUE;
		} else if (!all_written) {
			/* client disconnected before it finished sending the
			   whole message. */
			ctx->failed = TRUE;
			mailbox_save_cancel(&ctx->save_ctx);
			client_disconnect(client, "EOF while appending");
		} else if (ctx->catenate) {
			/* CATENATE isn't finished yet */
		} else if (mailbox_save_finish(&ctx->save_ctx) < 0) {
			ctx->failed = TRUE;
			client_send_storage_error(cmd, ctx->storage);
		}

		if (client->input->closed) {
			cmd_append_finish(ctx);
			return TRUE;
		}

		/* prepare for next message (part) */
		ctx->message_input = FALSE;
		imap_parser_reset(ctx->save_parser);

		if (ctx->catenate) {
			cmd->func = cmd_append_continue_catenate;
			return cmd_append_continue_catenate(cmd);
		}

		i_stream_unref(&ctx->input);
		cmd->func = cmd_append_continue_parsing;
		return cmd_append_continue_parsing(cmd);
	}
	return FALSE;
}

bool cmd_append(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
        struct cmd_append_context *ctx;
	const char *mailbox;

	if (client->syncing) {
		/* if transaction is created while its view is synced,
		   appends aren't allowed for it. */
		cmd->state = CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY;
		return FALSE;
	}

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	/* we keep the input locked all the time */
	client->input_lock = cmd;

	ctx = p_new(cmd->pool, struct cmd_append_context, 1);
	ctx->cmd = cmd;
	ctx->client = client;
	ctx->started = ioloop_time;
	if (client_open_save_dest_box(cmd, mailbox, &ctx->box) < 0)
		ctx->failed = TRUE;
	else {
		ctx->storage = mailbox_get_storage(ctx->box);

		ctx->t = mailbox_transaction_begin(ctx->box,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL |
					MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS);
	}

	io_remove(&client->io);
	client->io = io_add(i_stream_get_fd(client->input), IO_READ,
			    client_input_append, cmd);
	/* append is special because we're only waiting on client input, not
	   client output, so disable the standard output handler until we're
	   finished */
	o_stream_unset_flush_callback(client->output);

	ctx->save_parser = imap_parser_create(client->input, client->output,
					      client->set->imap_max_line_length);

	cmd->func = cmd_append_continue_parsing;
	cmd->context = ctx;
	return cmd_append_continue_parsing(cmd);
}
