/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

/* Parse next digits in string into integer. Returns FALSE if the integer
   becomes too big and wraps. */
static int read_uoff_t(char **p, uoff_t *value)
{
	uoff_t prev;

	*value = 0;
	while (**p >= '0' && **p <= '9') {
		prev = *value;
		*value = *value * 10 + (**p - '0');

		if (*value < prev)
			return FALSE;

		(*p)++;
	}

	return TRUE;
}

/* BODY[] and BODY.PEEK[] items. item points to next character after '[' */
static int parse_body_section(Client *client, const char *item,
			      MailFetchData *data, int peek)
{
	MailFetchBodyData *body;
	uoff_t num;
	const char *section;
	char *p;

	body = t_new(MailFetchBodyData, 1);
	body->peek = peek;

	p = t_strdup_noconst(item);

	/* read section */
	body->section = p;
	for (section = p; *p != ']'; p++) {
		if (*p == '\0') {
			client_send_tagline(client, t_strconcat(
				"BAD Missing ']' with ", item, NULL));
			return FALSE;
		}
	}
	*p++ = '\0';

	/* <start.end> */
	body->skip = 0;
	body->max_size = (uoff_t)-1;
	if (*p != '<' && *p != '\0') {
		client_send_tagline(client, t_strconcat(
			"BAD Unexpected character after ']' with ",
			item, NULL));
	} else if (*p == '<') {
		/* read start */
		p++;

		body->skip_set = TRUE;
		if (!read_uoff_t(&p, &num) || num > OFF_T_MAX) {
			/* wrapped */
			client_send_tagline(client, t_strconcat(
				"BAD Too big partial start with ", item, NULL));
			return FALSE;
		}
		body->skip = num;

		if (*p == '.') {
			/* read end */
			p++;
			if (!read_uoff_t(&p, &num) || num > OFF_T_MAX) {
				/* wrapped */
				client_send_tagline(client, t_strconcat(
					"BAD Too big partial end with ",
					item, NULL));
				return FALSE;
			}

                        body->max_size = num;
		}

		if (*p != '>') {
			client_send_tagline(client, t_strconcat(
				"BAD Invalid partial ", item, NULL));
			return FALSE;
		}
	}

	body->next = data->body_sections;
	data->body_sections = body;

	return TRUE;
}

static int parse_arg(Client *client, ImapArg *arg, MailFetchData *data)
{
	char *item;

	if (arg->type != IMAP_ARG_ATOM) {
		client_send_command_error(client,
					  "FETCH list contains non-atoms.");
		return FALSE;
	}

	item = arg->data.str;
	str_ucase(item);

	switch (*item) {
	case 'A':
		if (strcmp(item, "ALL") == 0) {
			data->flags = TRUE;
			data->internaldate = TRUE;
			data->rfc822_size = TRUE;
			data->envelope = TRUE;
		} else
			item = NULL;
		break;
	case 'B':
		/* all start with BODY so skip it */
		if (strncmp(item, "BODY", 4) != 0) {
			item = NULL;
			break;
		}
		item += 4;

		if (*item == '\0') {
			/* BODY */
			data->body = TRUE;
		} else if (*item == '[') {
			/* BODY[...] */
			if (!parse_body_section(client, item+1, data, FALSE))
				return FALSE;
		} else if (strncmp(item, ".PEEK[", 6) == 0) {
			/* BODY.PEEK[..] */
			if (!parse_body_section(client, item+6, data, TRUE))
				return FALSE;
		} else if (strcmp(item, "STRUCTURE") == 0) {
			/* BODYSTRUCTURE */
			data->bodystructure = TRUE;
		} else
			item = NULL;
		break;
	case 'E':
		if (strcmp(item, "ENVELOPE") == 0)
			data->envelope = TRUE;
		else
			item = NULL;
		break;
	case 'F':
		if (strcmp(item, "FLAGS") == 0)
			data->flags = TRUE;
		else if (strcmp(item, "FAST") == 0) {
			data->flags = TRUE;
			data->internaldate = TRUE;
			data->rfc822_size = TRUE;
		} else if (strcmp(item, "FULL") == 0) {
			data->flags = TRUE;
			data->internaldate = TRUE;
			data->rfc822_size = TRUE;
			data->envelope = TRUE;
			data->body = TRUE;
		} else
			item = NULL;
		break;
	case 'I':
		if (strcmp(item, "INTERNALDATE") == 0)
			data->internaldate = TRUE;
		else
			item = NULL;
		break;
	case 'R':
		/* all start with RFC822 so skip it */
		if (strncmp(item, "RFC822", 6) != 0) {
			item = NULL;
			break;
		}
		item += 6;

		if (*item == '\0') {
			/* RFC822 */
			data->rfc822 = TRUE;
			break;
		}

		/* only items beginning with "RFC822." left */
		if (*item != '.') {
			item = NULL;
			break;
		}
		item++;

		if (strcmp(item, "HEADER") == 0)
			data->rfc822_header = TRUE;
		else if (strcmp(item, "SIZE") == 0)
			data->rfc822_size = TRUE;
		else if (strcmp(item, "TEXT") == 0)
			data->rfc822_text = TRUE;
		else
			item = NULL;
		break;
	case 'U':
		if (strcmp(item, "UID") == 0)
			data->uid = TRUE;
		else
			item = NULL;
		break;
	default:
		item = NULL;
		break;
	}

	if (item == NULL) {
		/* unknown item */
		client_send_tagline(client, t_strconcat(
			"BAD Invalid item ", arg->data.str, NULL));
		return FALSE;
	}

	return TRUE;
}

int cmd_fetch(Client *client)
{
	ImapArg *args;
	ImapArgList *list;
	MailFetchData data;
	const char *messageset;
	int all_found;

	if (!client_read_args(client, 2, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	messageset = imap_arg_string(&args[0]);
	if (messageset == NULL ||
	    (args[1].type != IMAP_ARG_LIST && args[1].type != IMAP_ARG_ATOM)) {
		client_send_command_error(client, "Invalid FETCH arguments.");
		return TRUE;
	}

	/* parse items argument */
	memset(&data, 0, sizeof(MailFetchData));
	if (args[1].type == IMAP_ARG_ATOM) {
		if (!parse_arg(client, &args[1], &data))
			return TRUE;
	} else {
		list = args[1].data.list;
		while (list != NULL) {
			ImapArg *arg = &list->arg;

			if (!parse_arg(client, arg, &data))
				return TRUE;

			list = list->next;
		}
	}

	data.messageset = messageset;
	data.uidset = client->cmd_uid;
	if (data.uidset)
                data.uid = TRUE;

	/* fetch it */
	if (client->mailbox->fetch(client->mailbox, &data,
				   client->outbuf, &all_found)) {
		/* NOTE: syncing isn't allowed here */
		client_send_tagline(client, all_found ? "OK Fetch completed." :
				    "NO Some of the requested messages "
				    "no longer exist.");
	} else {
		client_send_storage_error(client);
	}

	return TRUE;
}
