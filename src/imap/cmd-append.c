/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "commands.h"
#include "imap-parser.h"
#include "imap-date.h"
#include "mail-storage.h"

#include <sys/time.h>

struct cmd_append_context {
	struct client *client;
        struct client_command_context *cmd;
	struct mail_storage *storage;
	struct mailbox *box;
        struct mailbox_transaction_context *t;

	struct istream *input;
	uoff_t msg_size;

	struct imap_parser *save_parser;
	struct mail_save_context *save_ctx;
};

static bool cmd_append_continue_message(struct client_command_context *cmd);

static void client_input(void *context)
{
	struct client *client = context;
	struct client_command_context *cmd = &client->cmd;

	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		if (client->command_pending) {
			/* message data, this is handled internally by
			   mailbox_save_continue() */
			break;
		}

		/* parameter word is longer than max. input buffer size.
		   this is most likely an error, so skip the new data
		   until newline is found. */
		client->input_skip_line = TRUE;

		client_send_command_error(cmd, "Too long argument.");
		_client_reset_command(client);
		break;
	}

	if (cmd->func(cmd)) {
		/* command execution was finished */
		client->bad_counter = 0;
		_client_reset_command(client);

		if (client->input_pending)
			_client_input(client);
	}
}

/* Returns -1 = error, 0 = need more data, 1 = successful. flags and
   internal_date may be NULL as a result, but mailbox and msg_size are always
   set when successful. */
static int validate_args(struct imap_arg *args, struct imap_arg_list **flags,
			 const char **internal_date, uoff_t *msg_size,
			 bool *nonsync)
{
	/* [<flags>] */
	if (args->type != IMAP_ARG_LIST)
		*flags = NULL;
	else {
		*flags = IMAP_ARG_LIST(args);
		args++;
	}

	/* [<internal date>] */
	if (args->type != IMAP_ARG_STRING)
		*internal_date = NULL;
	else {
		*internal_date = IMAP_ARG_STR(args);
		args++;
	}

	if (args->type != IMAP_ARG_LITERAL_SIZE &&
	    args->type != IMAP_ARG_LITERAL_SIZE_NONSYNC) {
		*nonsync = FALSE;
		return FALSE;
	}

	*nonsync = args->type == IMAP_ARG_LITERAL_SIZE_NONSYNC;
	*msg_size = IMAP_ARG_LITERAL_SIZE(args);
	return TRUE;
}

static void cmd_append_finish(struct cmd_append_context *ctx)
{
	ctx->client->input_skip_line = TRUE;

	io_remove(ctx->client->io);
	ctx->client->io = NULL;

        imap_parser_destroy(ctx->save_parser);

	if (ctx->input != NULL)
		i_stream_unref(ctx->input);

	if (ctx->save_ctx != NULL)
		mailbox_save_cancel(ctx->save_ctx);

	if (ctx->t != NULL)
		mailbox_transaction_rollback(ctx->t);

	if (ctx->box != ctx->cmd->client->mailbox && ctx->box != NULL)
		mailbox_close(ctx->box);
}

static bool cmd_append_continue_cancel(struct client_command_context *cmd)
{
	struct cmd_append_context *ctx = cmd->context;
	size_t size;

	(void)i_stream_read(ctx->input);
	(void)i_stream_get_data(ctx->input, &size);
	i_stream_skip(ctx->input, size);

	if (ctx->input->v_offset == ctx->msg_size || ctx->input->closed) {
		cmd_append_finish(ctx);
		return TRUE;
	}
	return FALSE;
}

static bool cmd_append_cancel(struct cmd_append_context *ctx, bool nonsync)
{
	if (!nonsync) {
		cmd_append_finish(ctx);
		return TRUE;
	}

	/* we have to read the nonsynced literal so we don't treat the message
	   data as commands. */
	ctx->input = i_stream_create_limit(default_pool, ctx->client->input,
					   ctx->client->input->v_offset,
					   ctx->msg_size);

	ctx->client->command_pending = TRUE;
	ctx->cmd->func = cmd_append_continue_cancel;
	ctx->cmd->context = ctx;
	return cmd_append_continue_cancel(ctx->cmd);
}

static bool cmd_append_continue_parsing(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	struct imap_arg *args;
	struct imap_arg_list *flags_list;
	enum mail_flags flags;
	const char *const *keywords_list;
	struct mail_keywords *keywords;
	const char *internal_date_str;
	time_t internal_date;
	int ret, timezone_offset;
	bool nonsync;

	/* if error occurs, the CRLF is already read. */
	client->input_skip_line = FALSE;

	/* [<flags>] [<internal date>] <message literal> */
	ret = imap_parser_read_args(ctx->save_parser, 0,
				    IMAP_PARSE_FLAG_LITERAL_SIZE, &args);
	if (ret == -1) {
		if (ctx->box != NULL)
			client_send_command_error(cmd, NULL);
		cmd_append_finish(ctx);
		return TRUE;
	}
	if (ret < 0) {
		/* need more data */
		return FALSE;
	}

	if (args->type == IMAP_ARG_EOL) {
		/* last message */
		enum mailbox_sync_flags sync_flags;

		if (ctx->box == NULL) {
			/* we failed earlier, error message is sent */
			cmd_append_finish(ctx);
			return TRUE;
		}

		ret = mailbox_transaction_commit(ctx->t, 0);
		ctx->t = NULL;
		if (ret < 0) {
			client_send_storage_error(cmd, ctx->storage);
			cmd_append_finish(ctx);
			return TRUE;
		}

		sync_flags = ctx->box == cmd->client->mailbox ?
			0 : MAILBOX_SYNC_FLAG_FAST;

		cmd_append_finish(ctx);
		return cmd_sync(cmd, sync_flags, 0, "OK Append completed.");
	}

	if (!validate_args(args, &flags_list, &internal_date_str,
			   &ctx->msg_size, &nonsync)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return cmd_append_cancel(ctx, nonsync);
	}

	if (ctx->box == NULL) {
		/* we failed earlier, make sure we just eat nonsync-literal
		   if it's given. */
		return cmd_append_cancel(ctx, nonsync);
	}

	if (flags_list != NULL) {
		if (!client_parse_mail_flags(cmd, flags_list->args,
					     &flags, &keywords_list))
			return cmd_append_cancel(ctx, nonsync);
		keywords = keywords_list == NULL ? NULL :
			mailbox_keywords_create(ctx->t, keywords_list);
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
		return cmd_append_cancel(ctx, nonsync);
	}

	if (ctx->msg_size == 0) {
		/* no message data, abort */
		client_send_tagline(cmd, "NO Append aborted.");
		cmd_append_finish(ctx);
		return TRUE;
	}

	if (!nonsync) {
		o_stream_send(client->output, "+ OK\r\n", 6);
		o_stream_flush(client->output);
		o_stream_uncork(client->output);
	}

	/* after literal comes CRLF, if we fail make sure we eat it away */
	client->input_skip_line = TRUE;

	/* save the mail */
	ctx->input = i_stream_create_limit(default_pool, client->input,
					   client->input->v_offset,
					   ctx->msg_size);
	ctx->save_ctx = mailbox_save_init(ctx->t, flags, keywords,
					  internal_date, timezone_offset, NULL,
					  ctx->input, FALSE);

	if (keywords != NULL)
		mailbox_keywords_free(ctx->t, keywords);

	client->command_pending = TRUE;
	cmd->func = cmd_append_continue_message;
	return cmd_append_continue_message(cmd);
}

static bool cmd_append_continue_message(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_append_context *ctx = cmd->context;
	size_t size;
	bool failed;

	if (ctx->save_ctx != NULL) {
		if (mailbox_save_continue(ctx->save_ctx) < 0) {
			/* we still have to finish reading the message
			   from client */
			mailbox_save_cancel(ctx->save_ctx);
			ctx->save_ctx = NULL;
		}
	}

	if (ctx->save_ctx == NULL) {
		(void)i_stream_read(ctx->input);
		(void)i_stream_get_data(ctx->input, &size);
		i_stream_skip(ctx->input, size);
	}

	if (ctx->input->eof || client->input->closed) {
		/* finished */
		bool all_written = ctx->input->v_offset == ctx->msg_size;

		i_stream_unref(ctx->input);
		ctx->input = NULL;

		if (ctx->save_ctx == NULL) {
			/* failed above */
			client_send_storage_error(cmd, ctx->storage);
			failed = TRUE;
		} else if (!all_written) {
			/* client disconnected before it finished sending the
			   whole message. */
			failed = TRUE;
			mailbox_save_cancel(ctx->save_ctx);
		} else if (mailbox_save_finish(ctx->save_ctx, NULL) < 0) {
			failed = TRUE;
			client_send_storage_error(cmd, ctx->storage);
		} else {
			failed = client->input->closed;
		}
		ctx->save_ctx = NULL;

		if (failed) {
			cmd_append_finish(ctx);
			return TRUE;
		}

		/* prepare for next message */
		client->command_pending = FALSE;
		imap_parser_reset(ctx->save_parser);
		cmd->func = cmd_append_continue_parsing;
		return cmd_append_continue_parsing(cmd);
	}

	return FALSE;
}

static struct mailbox *
get_mailbox(struct client_command_context *cmd, const char *name)
{
	struct mail_storage *storage;
	struct mailbox *box;

	if (!client_verify_mailbox_name(cmd, name, TRUE, FALSE))
		return NULL;

	storage = client_find_storage(cmd, &name);
	if (storage == NULL)
		return NULL;

	if (cmd->client->mailbox != NULL &&
	    mailbox_equals(cmd->client->mailbox, storage, name))
		return cmd->client->mailbox;

	box = mailbox_open(storage, name, NULL, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT);
	if (box == NULL) {
		client_send_storage_error(cmd, storage);
		return NULL;
	}
	return box;
}

bool cmd_append(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
        struct cmd_append_context *ctx;
	struct mailbox_status status;
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	ctx = p_new(cmd->pool, struct cmd_append_context, 1);
	ctx->cmd = cmd;
	ctx->client = client;
	ctx->box = get_mailbox(cmd, mailbox);
	if (ctx->box != NULL) {
		ctx->storage = mailbox_get_storage(ctx->box);

		if (mailbox_get_status(ctx->box, STATUS_KEYWORDS,
				       &status) < 0) {
			client_send_storage_error(cmd, ctx->storage);
			mailbox_close(ctx->box);
			ctx->box = NULL;
		} else {
			client_save_keywords(&client->keywords,
					     status.keywords);
		}
		ctx->t = ctx->box == NULL ? NULL :
			mailbox_transaction_begin(ctx->box,
				MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	}

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input), IO_READ,
			    client_input, client);
	/* append is special because we're only waiting on client input, not
	   client output, so disable the standard output handler until we're
	   finished */
	o_stream_set_flush_callback(client->output, NULL, NULL);

	ctx->save_parser = imap_parser_create(client->input, client->output,
					      imap_max_line_length);

	cmd->func = cmd_append_continue_parsing;
	cmd->context = ctx;
	return cmd_append_continue_parsing(cmd);
}
