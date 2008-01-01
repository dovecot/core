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
	struct mail_search_arg *sargs;
	const struct imap_arg *args;
	int args_count;
	pool_t pool;
	const char *error, *charset, *str;

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

	pool = pool_alloconly_create("mail_search_args", 2048);

	sargs = imap_search_args_build(pool, client->mailbox, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(cmd, t_strconcat("NO ", error, NULL));
	} else if (imap_thread(cmd, charset, sargs, threading) == 0) {
		pool_unref(&pool);
		return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
				(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
				0, "OK Thread completed.");
	} else {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
	}

	pool_unref(&pool);
	return TRUE;
}
