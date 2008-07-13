/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "buffer.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-sort.h"

struct sort_name {
	enum mail_sort_type type;
	const char *name;
};

static struct sort_name sort_names[] = {
	{ MAIL_SORT_ARRIVAL,		"arrival" },
	{ MAIL_SORT_CC,			"cc" },
	{ MAIL_SORT_DATE,		"date" },
	{ MAIL_SORT_FROM,		"from" },
	{ MAIL_SORT_SIZE,		"size" },
	{ MAIL_SORT_SUBJECT,		"subject" },
	{ MAIL_SORT_TO,			"to" },
	{ MAIL_SORT_SEARCH_SCORE,	"x-score" },

	{ MAIL_SORT_END,		NULL }
};

static int
get_sort_program(struct client_command_context *cmd,
		 const struct imap_arg *args,
		 enum mail_sort_type program[MAX_SORT_PROGRAM_SIZE])
{
	enum mail_sort_type mask = 0;
	unsigned int i, pos;
	bool reverse, last_reverse;

	if (args->type == IMAP_ARG_EOL) {
		/* empyty list */
		client_send_command_error(cmd, "Empty sort program.");
		return -1;
	}

	pos = 0; reverse = last_reverse = FALSE;
	for (; args->type == IMAP_ARG_ATOM || args->type == IMAP_ARG_STRING;
	     args++) {
		const char *arg = IMAP_ARG_STR(args);

		last_reverse = strcasecmp(arg, "reverse") == 0;
		if (last_reverse) {
			reverse = !reverse;
			continue;
		}

		for (i = 0; sort_names[i].type != MAIL_SORT_END; i++) {
			if (strcasecmp(arg, sort_names[i].name) == 0)
				break;
		}

		if (sort_names[i].type == MAIL_SORT_END) {
			client_send_command_error(cmd, t_strconcat(
				"Unknown sort argument: ", arg, NULL));
			return -1;
		}

		if ((mask & sort_names[i].type) != 0)
			continue;
		mask |= sort_names[i].type;

		/* @UNSAFE: mask check should prevent us from ever
		   overflowing */
		i_assert(pos < MAX_SORT_PROGRAM_SIZE-1);
		program[pos++] = sort_names[i].type |
			(reverse ? MAIL_SORT_FLAG_REVERSE : 0);
		reverse = FALSE;
	}
	if (last_reverse) {
		client_send_command_error(cmd, "Sort list ends with REVERSE.");
		return -1;
	}
	program[pos++] = MAIL_SORT_END;

	if (args->type != IMAP_ARG_EOL) {
		client_send_command_error(cmd,
					  "Invalid sort list argument.");
		return -1;
	}

	return 0;
}

bool cmd_sort(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_search_args *sargs;
	enum mail_sort_type sorting[MAX_SORT_PROGRAM_SIZE];
	const struct imap_arg *args;
	int args_count;
	const char *charset;
	int ret;

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

	/* sort program */
	if (args->type != IMAP_ARG_LIST) {
		client_send_command_error(cmd, "Invalid sort argument.");
		return TRUE;
	}

	if (get_sort_program(cmd, IMAP_ARG_LIST_ARGS(args), sorting) < 0)
		return TRUE;
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

	ret = imap_sort(cmd, sargs, sorting);
	mail_search_args_unref(&sargs);
	if (ret < 0) {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
			0, "OK Sort completed.");
}
