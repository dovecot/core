/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-fetch.h"

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

static int check_header_section(const char *section)
{
	/* HEADER, HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */
	if (*section == '\0')
		return TRUE;

	if (strncmp(section, ".FIELDS", 7) != 0)
		return FALSE;

	section += 7;
	if (strncmp(section, ".NOT", 4) == 0)
		section += 4;

	while (*section == ' ') section++;
	if (*section++ != '(')
		return FALSE;

	while (*section != '\0' && *section != ')') {
		if (*section == '(')
			return FALSE;
		section++;
	}

	if (*section++ != ')')
		return FALSE;

	if (*section != '\0')
		return FALSE;
	return TRUE;
}

static int check_section(struct client *client, const char *section,
			 enum mail_fetch_field *fetch_data)
{
	if (*section == '\0') {
		*fetch_data |= MAIL_FETCH_STREAM_HEADER |
			MAIL_FETCH_STREAM_BODY;
		return TRUE;
	}

	if (strcmp(section, "TEXT") == 0) {
		*fetch_data |= MAIL_FETCH_STREAM_BODY;
		return TRUE;
	}

	if (strncmp(section, "HEADER", 6) == 0) {
		*fetch_data |= MAIL_FETCH_STREAM_HEADER;
		if (check_header_section(section+6))
			return TRUE;
	} else if (*section >= '0' && *section <= '9') {
		*fetch_data |= MAIL_FETCH_STREAM_BODY |
			MAIL_FETCH_MESSAGE_PARTS;

		while ((*section >= '0' && *section <= '9') ||
		       *section == '.') section++;

		if (*section == '\0')
			return TRUE;
		if (strcmp(section, "MIME") == 0 ||
		    strcmp(section, "TEXT") == 0)
			return TRUE;

		if (strncmp(section, "HEADER", 6) == 0 &&
		    check_header_section(section+6))
			return TRUE;
	}

	client_send_tagline(client, t_strconcat(
		"BAD Invalid BODY[] section: ", section, NULL));
	return FALSE;
}

/* BODY[] and BODY.PEEK[] items. item points to next character after '[' */
static int parse_body_section(struct client *client, const char *item, int peek,
			      enum mail_fetch_field *fetch_data,
			      struct imap_fetch_body_data ***bodies)
{
	/* @UNSAFE */
	struct imap_fetch_body_data *body;
	uoff_t num;
	char *p;

	body = t_new(struct imap_fetch_body_data, 1);
	body->peek = peek;

	p = t_strdup_noconst(item);

	/* read section */
	body->section = p;
	for (; *p != ']'; p++) {
		if (*p == '\0') {
			client_send_tagline(client, t_strconcat(
				"BAD Missing ']' with ", item, NULL));
			return FALSE;
		}
	}
	*p++ = '\0';

	if (!check_section(client, body->section, fetch_data))
		return FALSE;

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

	**bodies = body;
	*bodies = &body->next;
	return TRUE;
}

static int parse_arg(struct client *client, struct imap_arg *arg,
		     enum mail_fetch_field *fetch_data,
		     enum imap_fetch_field *imap_data,
		     struct imap_fetch_body_data ***bodies)
{
	char *item;

	if (arg->type != IMAP_ARG_ATOM) {
		client_send_command_error(client,
					  "FETCH list contains non-atoms.");
		return FALSE;
	}

	item = str_ucase(IMAP_ARG_STR(arg));

	switch (*item) {
	case 'A':
		if (strcmp(item, "ALL") == 0) {
			*fetch_data |= MAIL_FETCH_FLAGS |
				MAIL_FETCH_RECEIVED_DATE |
				MAIL_FETCH_SIZE |
				MAIL_FETCH_IMAP_ENVELOPE;
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
			*fetch_data |= MAIL_FETCH_IMAP_BODY;
		} else if (*item == '[') {
			/* BODY[...] */
			if (!parse_body_section(client, item+1, FALSE,
						fetch_data, bodies))
				return FALSE;
		} else if (strncmp(item, ".PEEK[", 6) == 0) {
			/* BODY.PEEK[..] */
			if (!parse_body_section(client, item+6, TRUE,
						fetch_data, bodies))
				return FALSE;
		} else if (strcmp(item, "STRUCTURE") == 0) {
			/* BODYSTRUCTURE */
			*fetch_data |= MAIL_FETCH_IMAP_BODYSTRUCTURE;
		} else
			item = NULL;
		break;
	case 'E':
		if (strcmp(item, "ENVELOPE") == 0)
			*fetch_data |= MAIL_FETCH_IMAP_ENVELOPE;
		else
			item = NULL;
		break;
	case 'F':
		if (strcmp(item, "FLAGS") == 0)
			*fetch_data |= MAIL_FETCH_FLAGS;
		else if (strcmp(item, "FAST") == 0) {
			*fetch_data |= MAIL_FETCH_FLAGS |
				MAIL_FETCH_RECEIVED_DATE |
				MAIL_FETCH_SIZE;
		} else if (strcmp(item, "FULL") == 0) {
			*fetch_data |= MAIL_FETCH_FLAGS |
				MAIL_FETCH_RECEIVED_DATE |
				MAIL_FETCH_SIZE |
				MAIL_FETCH_IMAP_ENVELOPE |
				MAIL_FETCH_IMAP_BODY;
		} else
			item = NULL;
		break;
	case 'I':
		if (strcmp(item, "INTERNALDATE") == 0)
			*fetch_data |= MAIL_FETCH_RECEIVED_DATE;
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
			*fetch_data |= MAIL_FETCH_STREAM_HEADER |
				MAIL_FETCH_STREAM_BODY;
			*imap_data |= IMAP_FETCH_RFC822;
			break;
		}

		/* only items beginning with "RFC822." left */
		if (*item != '.') {
			item = NULL;
			break;
		}
		item++;

		if (strcmp(item, "HEADER") == 0) {
			*fetch_data |= MAIL_FETCH_STREAM_HEADER;
			*imap_data |= IMAP_FETCH_RFC822_HEADER;
		} else if (strcmp(item, "TEXT") == 0) {
			*fetch_data |= MAIL_FETCH_STREAM_BODY;
			*imap_data |= IMAP_FETCH_RFC822_TEXT;
		} else if (strcmp(item, "SIZE") == 0)
			*fetch_data |= MAIL_FETCH_SIZE;
		else
			item = NULL;
		break;
	case 'U':
		if (strcmp(item, "UID") == 0)
			*imap_data |= IMAP_FETCH_UID;
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
			"BAD Invalid item ", IMAP_ARG_STR(arg), NULL));
		return FALSE;
	}

	return TRUE;
}

int cmd_fetch(struct client *client)
{
	struct imap_arg *args, *listargs;
	enum mail_fetch_field fetch_data;
	enum imap_fetch_field imap_data;
	struct imap_fetch_body_data *bodies, **bodies_p;
	const char *messageset;
	int ret;

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
	fetch_data = 0; imap_data = 0; bodies = NULL; bodies_p = &bodies;
	if (args[1].type == IMAP_ARG_ATOM) {
		if (!parse_arg(client, &args[1], &fetch_data,
			       &imap_data, &bodies_p))
			return TRUE;
	} else {
		listargs = IMAP_ARG_LIST(&args[1])->args;
		while (listargs->type != IMAP_ARG_EOL) {
			if (!parse_arg(client, listargs, &fetch_data,
				       &imap_data, &bodies_p))
				return TRUE;

			listargs++;
		}
	}

	ret = imap_fetch(client, fetch_data, imap_data,
			 bodies, messageset, client->cmd_uid);
	if (ret >= 0) {
		/* NOTE: syncing isn't allowed here */
                client_sync_without_expunges(client);
		client_send_tagline(client, ret > 0 ? "OK Fetch completed." :
			"NO Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(client);
	}

	return TRUE;
}
