/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-parser.h"
#include "imap-parser.h"
#include "imap-envelope.h"
#include "imap-quote.h"

struct message_part_envelope_data {
	pool_t pool;

	const char *date, *subject;
	struct message_address *from, *sender, *reply_to;
	struct message_address *to, *cc, *bcc;

	const char *in_reply_to, *message_id;
};

const char *imap_envelope_headers[] = {
	"Date", "Subject", "From", "Sender", "Reply-To",
	"To", "Cc", "Bcc", "In-Reply-To", "Message-ID",
	NULL
};

bool imap_envelope_get_field(const char *name, enum imap_envelope_field *ret)
{
	*ret = (enum imap_envelope_field)-1;

	switch (*name) {
	case 'B':
	case 'b':
		if (strcasecmp(name, "Bcc") == 0)
			*ret = IMAP_ENVELOPE_BCC;
		break;
	case 'C':
	case 'c':
		if (strcasecmp(name, "Cc") == 0)
			*ret = IMAP_ENVELOPE_CC;
		break;
	case 'D':
	case 'd':
		if (strcasecmp(name, "Date") == 0)
			*ret = IMAP_ENVELOPE_DATE;
		break;
	case 'F':
	case 'f':
		if (strcasecmp(name, "From") == 0)
			*ret = IMAP_ENVELOPE_FROM;
		break;
	case 'I':
	case 'i':
		if (strcasecmp(name, "In-reply-to") == 0)
			*ret = IMAP_ENVELOPE_IN_REPLY_TO;
		break;
	case 'M':
	case 'm':
		if (strcasecmp(name, "Message-id") == 0)
			*ret = IMAP_ENVELOPE_MESSAGE_ID;
		break;
	case 'R':
	case 'r':
		if (strcasecmp(name, "Reply-to") == 0)
			*ret = IMAP_ENVELOPE_REPLY_TO;
		break;
	case 'S':
	case 's':
		if (strcasecmp(name, "Subject") == 0)
			*ret = IMAP_ENVELOPE_SUBJECT;
		if (strcasecmp(name, "Sender") == 0)
			*ret = IMAP_ENVELOPE_SENDER;
		break;
	case 'T':
	case 't':
		if (strcasecmp(name, "To") == 0)
			*ret = IMAP_ENVELOPE_TO;
		break;
	}

	return *ret != (enum imap_envelope_field)-1;
}

void imap_envelope_parse_header(pool_t pool,
				struct message_part_envelope_data **data,
				struct message_header_line *hdr)
{
	struct message_part_envelope_data *d;
	enum imap_envelope_field field;
	struct message_address **addr_p;
	const char **str_p;

	if (*data == NULL) {
		*data = p_new(pool, struct message_part_envelope_data, 1);
		(*data)->pool = pool;
	}

	if (hdr == NULL || !imap_envelope_get_field(hdr->name, &field))
		return;

	if (hdr->continues) {
		/* wait for full value */
		hdr->use_full_value = TRUE;
		return;
	}

	d = *data;
	addr_p = NULL; str_p = NULL;
	switch (field) {
	case IMAP_ENVELOPE_DATE:
		str_p = &d->date;
		break;
	case IMAP_ENVELOPE_SUBJECT:
		str_p = &d->subject;
		break;
	case IMAP_ENVELOPE_MESSAGE_ID:
		str_p = &d->message_id;
		break;
	case IMAP_ENVELOPE_IN_REPLY_TO:
		str_p = &d->in_reply_to;
		break;

	case IMAP_ENVELOPE_CC:
		addr_p = &d->cc;
		break;
	case IMAP_ENVELOPE_BCC:
		addr_p = &d->bcc;
		break;
	case IMAP_ENVELOPE_FROM:
		addr_p = &d->from;
		break;
	case IMAP_ENVELOPE_SENDER:
		addr_p = &d->sender;
		break;
	case IMAP_ENVELOPE_TO:
		addr_p = &d->to;
		break;
	case IMAP_ENVELOPE_REPLY_TO:
		addr_p = &d->reply_to;
		break;
	case IMAP_ENVELOPE_FIELDS:
		break;
	}

	if (addr_p != NULL) {
		*addr_p = message_address_parse(pool, hdr->full_value,
						hdr->full_value_len,
						UINT_MAX, TRUE);
	} else if (str_p != NULL) T_BEGIN {
		string_t *str = t_str_new(128);

		if (str_p != &d->subject) {
			imap_append_string(str,
				t_strndup(hdr->full_value, hdr->full_value_len));
		} else {
			imap_append_string_for_humans(str,
				hdr->full_value, hdr->full_value_len);
		}
		*str_p = p_strdup(pool, str_c(str));
	} T_END;
}

static void imap_write_address(string_t *str, struct message_address *addr)
{
	if (addr == NULL) {
		str_append(str, "NIL");
		return;
	}

	str_append_c(str, '(');
	while (addr != NULL) {
		str_append_c(str, '(');
		if (addr->name == NULL)
			str_append(str, "NIL");
		else {
			imap_append_string_for_humans(str,
				(const void *)addr->name, strlen(addr->name));
		}
		str_append_c(str, ' ');
		imap_append_nstring(str, addr->route);
		str_append_c(str, ' ');
		imap_append_nstring(str, addr->mailbox);
		str_append_c(str, ' ');
		imap_append_nstring(str, addr->domain);
		str_append_c(str, ')');

		addr = addr->next;
	}
	str_append_c(str, ')');
}

void imap_envelope_write_part_data(struct message_part_envelope_data *data,
				   string_t *str)
{
#define NVL(str, nullstr) ((str) != NULL ? (str) : (nullstr))
	static const char *empty_envelope =
		"NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL";

	if (data == NULL) {
		str_append(str, empty_envelope);
		return;
	}

	str_append(str, NVL(data->date, "NIL"));
	str_append_c(str, ' ');
	str_append(str, NVL(data->subject, "NIL"));

	str_append_c(str, ' ');
	imap_write_address(str, data->from);
	str_append_c(str, ' ');
	imap_write_address(str, NVL(data->sender, data->from));
	str_append_c(str, ' ');
	imap_write_address(str, NVL(data->reply_to, data->from));
	str_append_c(str, ' ');
	imap_write_address(str, data->to);
	str_append_c(str, ' ');
	imap_write_address(str, data->cc);
	str_append_c(str, ' ');
	imap_write_address(str, data->bcc);

	str_append_c(str, ' ');
	str_append(str, NVL(data->in_reply_to, "NIL"));
	str_append_c(str, ' ');
	str_append(str, NVL(data->message_id, "NIL"));
}

