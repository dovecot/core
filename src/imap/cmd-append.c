/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "commands.h"
#include "imap-parser.h"
#include "imap-date.h"
#include "mail-storage.h"

#include <sys/time.h>

/* Returns -1 = error, 0 = need more data, 1 = successful. flags and
   internal_date may be NULL as a result, but mailbox and msg_size are always
   set when successful. */
static int validate_args(struct imap_arg *args, struct imap_arg_list **flags,
			 const char **internal_date, uoff_t *msg_size,
			 int *nonsync)
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
	    args->type != IMAP_ARG_LITERAL_SIZE_NONSYNC)
		return FALSE;

	*nonsync = args->type == IMAP_ARG_LITERAL_SIZE_NONSYNC;
	*msg_size = IMAP_ARG_LITERAL_SIZE(args);
	return TRUE;
}

int cmd_append(struct client *client)
{
	struct mail_storage *storage;
	struct mailbox *box;
	struct mailbox_status status;
        struct mailbox_transaction_context *t;
	struct imap_parser *save_parser;
	struct imap_arg *args;
	struct imap_arg_list *flags_list;
        struct mailbox_keywords old_flags;
	struct mail_full_flags flags;
	struct istream *input;
	time_t internal_date;
	const char *mailbox, *internal_date_str;
	uoff_t msg_size;
	unsigned int count;
	int ret, failed, timezone_offset, nonsync;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	storage = client_find_storage(client, mailbox);
	if (storage == NULL)
		return TRUE;

	box = mailbox_open(storage, mailbox, MAILBOX_OPEN_FAST);
	if (box == NULL) {
		client_send_storage_error(client, storage);
		return TRUE;
	}

	if (mailbox_get_status(box, STATUS_KEYWORDS, &status) < 0) {
		client_send_storage_error(client, storage);
		mailbox_close(box);
		return TRUE;
	}
	memset(&old_flags, 0, sizeof(old_flags));
        old_flags.pool = pool_datastack_create();
	client_save_keywords(&old_flags, status.keywords,
			     status.keywords_count);

	t = mailbox_transaction_begin(box, FALSE);

	/* if error occurs, the CRLF is already read. */
	client->input_skip_line = FALSE;

	count = 0;
	failed = TRUE;
	save_parser = imap_parser_create(client->input, client->output,
					 imap_max_line_length);

	for (;;) {
		/* [<flags>] [<internal date>] <message literal> */
		imap_parser_reset(save_parser);
		for (;;) {
			ret = imap_parser_read_args(save_parser, 0,
						   IMAP_PARSE_FLAG_LITERAL_SIZE,
						   &args);
			if (ret >= 0)
				break;
			if (ret == -1) {
				client_send_command_error(client, NULL);
				break;
			}

			/* need more data */
			ret = i_stream_read(client->input);
			if (ret == -2) {
				client_send_command_error(client,
							  "Too long argument.");
				break;
			}
			if (ret < 0) {
				/* disconnected */
				client->cmd_error = TRUE;
				break;
			}
		}

		if (client->cmd_error)
			break;

		if (args->type == IMAP_ARG_EOL) {
			/* last one */
			if (count > 0)
				failed = FALSE;
			client->input_skip_line = TRUE;
			break;
		}

		if (!validate_args(args, &flags_list, &internal_date_str,
				   &msg_size, &nonsync)) {
			/* error */
			client_send_command_error(client, "Invalid arguments.");
			break;
		}

		if (flags_list != NULL) {
			if (!client_parse_mail_flags(client, flags_list->args,
						     &old_flags, &flags))
				break;
		} else {
			memset(&flags, 0, sizeof(flags));
		}

		if (internal_date_str == NULL) {
			/* no time given, default to now. */
			internal_date = (time_t)-1;
			timezone_offset = 0;
		} else if (!imap_parse_datetime(internal_date_str,
						&internal_date,
						&timezone_offset)) {
			client_send_tagline(client,
					    "BAD Invalid internal date.");
			break;
		}

		if (msg_size == 0) {
			/* no message data, abort */
			client_send_tagline(client, "NO Append aborted.");
			break;
		}

		if (!nonsync) {
			o_stream_send(client->output, "+ OK\r\n", 6);
			o_stream_flush(client->output);
		}

		/* save the mail */
		input = i_stream_create_limit(default_pool, client->input,
					      client->input->v_offset,
					      msg_size);
		if (mailbox_save(t, &flags, internal_date, timezone_offset,
				 NULL, input) < 0) {
			i_stream_unref(input);
			client_send_storage_error(client, storage);
			break;
		}
		i_stream_unref(input);

		if (client->input->closed)
			break;

		count++;
	}
        imap_parser_destroy(save_parser);

	if (failed)
		mailbox_transaction_rollback(t);
	else {
		if (mailbox_transaction_commit(t) < 0) {
			failed = TRUE;
			client_send_storage_error(client, storage);
		}
	}

	mailbox_close(box);

	if (!failed) {
		client_sync_full(client);
		client_send_tagline(client, "OK Append completed.");
	}
	return TRUE;
}
