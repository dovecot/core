/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "mail-search.h"
#include "mail-sort.h"

typedef struct {
	MailSortType type;
	const char *name;
} SortName;

static SortName sort_names[] = {
	{ MAIL_SORT_ARRIVAL,	"arrival" },
	{ MAIL_SORT_CC,		"cc" },
	{ MAIL_SORT_DATE,	"date" },
	{ MAIL_SORT_FROM,	"from" },
	{ MAIL_SORT_SIZE,	"size" },
	{ MAIL_SORT_SUBJECT,	"subject" },
	{ MAIL_SORT_TO,		"to" },

	{ MAIL_SORT_REVERSE,	"reverse" },
	{ MAIL_SORT_END,	NULL }
};

static MailSortType *get_sort_program(Client *client, ImapArg *args)
{
	MailSortType *program, *temp_prog;
	size_t program_alloc, program_size;
	int i;

	program_alloc = 32; program_size = 0;
	program = t_new(MailSortType, program_alloc+1);

	while (args->type == IMAP_ARG_ATOM || args->type == IMAP_ARG_STRING) {
		const char *arg = args->data.str;

		for (i = 0; sort_names[i].type != MAIL_SORT_END; i++) {
			if (strcasecmp(arg, sort_names[i].name) == 0)
				break;
		}

		if (sort_names[i].type == MAIL_SORT_END) {
			client_send_command_error(client, t_strconcat(
				"Unknown sort argument: ", arg, NULL));
			return NULL;
		}

		if (program_size == program_alloc) {
			program_alloc *= 2;
			if (!t_try_realloc(program, program_alloc+1)) {
				temp_prog = t_new(MailSortType, program_alloc);
				memcpy(temp_prog, program,
				       sizeof(MailSortType) * program_size);
				program = temp_prog;
			}
		}
		program[program_size++] = sort_names[i].type;
		args++;
	}

	program[program_size] = MAIL_SORT_END;

	if (args->type != IMAP_ARG_EOL) {
		client_send_command_error(client,
					  "Invalid sort list argument.");
		return NULL;
	}

	return program;
}

int cmd_sort(Client *client)
{
	MailSearchArg *sargs;
	MailSortType *sorting;
	ImapArg *args;
	int args_count;
	Pool pool;
	const char *error, *charset;

	args_count = imap_parser_read_args(client->parser, 0, 0, &args);
	if (args_count == -2)
		return FALSE;

	if (args_count < 3) {
		client_send_command_error(client,
					  "Missing or invalid arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(client))
		return TRUE;

	/* sort program */
	if (args->type != IMAP_ARG_LIST) {
		client_send_command_error(client, "Invalid sort argument.");
		return TRUE;
	}

	sorting = get_sort_program(client, args->data.list->args);
	if (sorting == NULL)
		return TRUE;
	args++;

	/* charset */
	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(client,
					  "Invalid charset argument.");
	}
	charset = args->data.str;
	args++;

	pool = pool_create("MailSortArgs", 2048, FALSE);

	sargs = mail_search_args_build(pool, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(client, t_strconcat("NO ", error, NULL));
	} else {
		if (client->mailbox->search(client->mailbox, charset,
					    sargs, sorting,
					    client->outbuf, client->cmd_uid)) {
			/* NOTE: syncing is allowed when returning UIDs */
			if (client->cmd_uid)
				client_sync_full(client);
			else
				client_sync_without_expunges(client);
			client_send_tagline(client, "OK Search completed.");
		} else {
			client_send_storage_error(client);
		}
	}

	pool_unref(pool);
	return TRUE;
}
