/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "obuffer.h"
#include "commands.h"
#include "imap-parser.h"
#include "imap-date.h"

/* Returns -1 = error, 0 = need more data, 1 = successful. flags and
   internal_date may be NULL as a result, but mailbox and msg_size are always
   set when successful. */
static int validate_args(Client *client, const char **mailbox,
			 ImapArgList **flags, const char **internal_date,
			 uoff_t *msg_size, unsigned int count)
{
	ImapArg *args;

	i_assert(count >= 2 && count <= 4);

	*flags = NULL;
	*internal_date = NULL;

	if (!client_read_args(client, count, IMAP_PARSE_FLAG_LITERAL_SIZE,
			      &args))
		return 0;

	switch (count) {
	case 2:
		/* do we have flags or internal date parameter? */
		if (args[1].type == IMAP_ARG_LIST ||
		    args[1].type == IMAP_ARG_STRING)
			return validate_args(client, mailbox, flags,
					     internal_date, msg_size, 3);

		break;
	case 3:
		/* do we have both flags and internal date? */
		if (args[1].type == IMAP_ARG_LIST &&
		    args[2].type == IMAP_ARG_STRING)
			return validate_args(client, mailbox, flags,
					     internal_date, msg_size, 4);

		if (args[1].type == IMAP_ARG_LIST)
			*flags = args[1].data.list;
		else if (args[1].type == IMAP_ARG_STRING)
			*internal_date = args[1].data.str;
		else
			return -1;
		break;
	case 4:
		/* we have all parameters */
		*flags = args[1].data.list;
		*internal_date = args[2].data.str;
		break;
	default:
		i_assert(0);
	}

	/* check that mailbox and message arguments are ok */
	*mailbox = imap_arg_string(&args[0]);
	if (*mailbox == NULL)
		return -1;

	if (args[count-1].type != IMAP_ARG_LITERAL_SIZE)
		return -1;

	*msg_size = args[count-1].data.literal_size;
	return 1;
}

int cmd_append(Client *client)
{
	ImapArgList *flags_list;
	Mailbox *box;
	MailFlags flags;
	time_t internal_date;
	const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT];
	const char *mailbox, *internal_date_str;
	uoff_t msg_size;
	int failed;

	/* <mailbox> [<flags>] [<internal date>] <message literal> */
	switch (validate_args(client, &mailbox, &flags_list,
			      &internal_date_str, &msg_size, 2)) {
	case -1:
		/* error */
		client_send_command_error(client, "Invalid APPEND arguments.");
		return TRUE;
	case 0:
		/* need more data */
		return FALSE;
	}

	if (flags_list != NULL) {
		if (!client_parse_mail_flags(client, flags_list->args,
					     flags_list->size,
					     &flags, custom_flags))
			return TRUE;
	} else {
		if (!client_parse_mail_flags(client, NULL, 0,
					     &flags, custom_flags))
			return TRUE;
	}

	if (internal_date_str == NULL) {
		/* no time given, default to now. */
		internal_date = ioloop_time;
	} else if (!imap_parse_datetime(internal_date_str, &internal_date)) {
		client_send_tagline(client, "BAD Invalid internal date.");
		return TRUE;
	}

	/* open the mailbox */
	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	box = client->storage->open_mailbox(client->storage,
					    mailbox, FALSE, TRUE);
	if (box == NULL) {
		client_send_storage_error(client);
		return TRUE;
	}

	o_buffer_send(client->outbuf, "+ OK\r\n", 6);
	o_buffer_flush(client->outbuf);

	/* save the mail */
	failed = !box->save(box, flags, custom_flags, internal_date,
			    client->inbuf, msg_size);
	box->close(box);

	if (failed) {
		client_send_storage_error(client);
	} else {
		client_sync_full(client);
		client_send_tagline(client, "OK Append completed.");
	}
	return TRUE;
}
