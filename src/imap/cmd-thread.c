/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "buffer.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-thread.h"

bool cmd_thread(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	enum mail_thread_type threading;
	struct mail_search_args *sargs;
	const struct imap_arg *args;
	int ret, args_count;
	const char *charset, *str;

	args_count = imap_parser_read_args(cmd->parser, 0, 0, &args);
	if (args_count == -2)
		return FALSE;
	client->input_lock = NULL;

	if (args_count < 3) {
		client_send_command_error(cmd, args_count < 0 ? NULL :
					  "Missing or invalid arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(cmd,
					  "Invalid thread algorithm argument.");
		return TRUE;
	}

	str = IMAP_ARG_STR(args);
	if (strcasecmp(str, "REFERENCES") == 0)
		threading = MAIL_THREAD_REFERENCES;
	else if (strcasecmp(str, "X-REFERENCES2") == 0)
		threading = MAIL_THREAD_REFERENCES2;
	else if (strcasecmp(str, "ORDEREDSUBJECT") == 0) {
		client_send_command_error(cmd,
			"ORDEREDSUBJECT threading is currently not supported.");
		return TRUE;
	} else {
		client_send_command_error(cmd, "Unknown thread algorithm.");
		return TRUE;
	}
	args++;

	/* charset */
	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(cmd,
					  "Invalid charset argument.");
		return TRUE;
	}
	charset = IMAP_ARG_STR(args);
	args++;

	ret = imap_search_args_build(cmd, args, charset, &sargs);
	if (ret <= 0)
		return ret < 0;

	ret = imap_thread(client->mailbox, cmd->uid, client->output,
			  sargs, threading);
	mail_search_args_unref(&sargs);
	if (ret < 0) {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
			0, "OK Thread completed.");
}
