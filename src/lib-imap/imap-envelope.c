/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

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
						(unsigned int)-1, TRUE);
	}

	if (str_p != NULL) {
		*str_p = imap_quote(pool, hdr->full_value,
				    hdr->full_value_len, TRUE);
	}
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
		imap_quote_append_string(str, addr->name, TRUE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, addr->route, TRUE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, addr->mailbox, TRUE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, addr->domain, TRUE);
		str_append_c(str, ')');

		addr = addr->next;
	}
	str_append_c(str, ')');
}

void imap_envelope_write_part_data(struct message_part_envelope_data *data,
				   string_t *str)
{
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

static bool imap_address_arg_append(const struct imap_arg *arg, string_t *str,
				    bool *in_group)
{
	const struct imap_arg *list_args;
	unsigned int list_count;
	const char *args[4];
	int i;

	if (!imap_arg_get_list_full(arg, &list_args, &list_count))
		return FALSE;

	/* we require 4 arguments, strings or NILs */
	if (list_count < 4)
		return FALSE;

	for (i = 0; i < 4; i++) {
		if (!imap_arg_get_nstring(&list_args[i], &args[i]))
			return FALSE;
	}

	if (*in_group && args[0] == NULL && args[1] == NULL &&
	    args[2] == NULL && args[3] == NULL) {
		/* end of group */
		str_append_c(str, ';');
		*in_group = FALSE;
		return TRUE;
	}

	if (str_len(str) > 0)
		str_append(str, ", ");

	if (!*in_group && args[0] == NULL && args[1] == NULL &&
	    args[2] != NULL && args[3] == NULL) {
		/* beginning of group */
		str_append(str, args[2]);
		str_append(str, ": ");
		*in_group = TRUE;
		return TRUE;
	}

	/* a) mailbox@domain
	   b) name <@route:mailbox@domain> */
	if (args[0] == NULL && args[1] == NULL) {
		if (args[2] != NULL)
			str_append(str, args[2]);
		if (args[3] != NULL) {
			str_append_c(str, '@');
			str_append(str, args[3]);
		}
	} else {
		if (args[0] != NULL) {
			str_append(str, args[0]);
			str_append_c(str, ' ');
		}

		str_append_c(str, '<');
		if (args[1] != NULL) {
			str_append_c(str, '@');
			str_append(str, args[1]);
			str_append_c(str, ':');
		}
		if (args[2] != NULL)
			str_append(str, args[2]);
		if (args[3] != NULL) {
			str_append_c(str, '@');
			str_append(str, args[3]);
		}
		str_append_c(str, '>');
	}
	return TRUE;
}

static const char *imap_envelope_parse_address(const struct imap_arg *arg)
{
	const struct imap_arg *list_args;
	string_t *str;
	bool in_group;

	if (!imap_arg_get_list(arg, &list_args))
		return NULL;

	in_group = FALSE;
	str = t_str_new(128);

	for (; !IMAP_ARG_IS_EOL(list_args); list_args++) {
		if (!imap_address_arg_append(list_args, str, &in_group))
			return NULL;
	}

	return str_c(str);
}

static const char *imap_envelope_parse_first_mailbox(const struct imap_arg *arg)
{
	const struct imap_arg *list_args;
	const char *str;
	unsigned int list_count;

	/* ((...)(...) ...) */
	if (!imap_arg_get_list(arg, &list_args))
		return NULL;
	if (IMAP_ARG_IS_EOL(list_args))
		return "";

	/* (name route mailbox domain) */
	if (!imap_arg_get_list_full(arg, &list_args, &list_count) ||
	    list_count != 4)
		return NULL;
	if (!imap_arg_get_nstring(&list_args[2], &str))
		return NULL;
	return t_strdup(str);
}

static bool
imap_envelope_parse_arg(const struct imap_arg *arg,
			enum imap_envelope_field field,
			const char *envelope,
			enum imap_envelope_result_type result_type,
			const char **result)
{
	const char *value = NULL;

	if (arg->type == IMAP_ARG_NIL) {
		*result = NULL;
		return TRUE;
	}

	switch (result_type) {
	case IMAP_ENVELOPE_RESULT_TYPE_STRING:
		if (field >= IMAP_ENVELOPE_FROM && field <= IMAP_ENVELOPE_BCC)
			value = imap_envelope_parse_address(arg);
		else {
			if (imap_arg_get_nstring(arg, &value))
				value = t_strdup(value);
		}
		break;
	case IMAP_ENVELOPE_RESULT_TYPE_FIRST_MAILBOX:
		i_assert(field >= IMAP_ENVELOPE_FROM &&
			 field <= IMAP_ENVELOPE_BCC);
		value = imap_envelope_parse_first_mailbox(arg);
		break;
	}

	*result = value;
	if (value != NULL)
		return TRUE;
	else {
		i_error("Invalid field %u in IMAP envelope: %s",
			field, envelope);
		return FALSE;
	}
}

bool imap_envelope_parse(const char *envelope, enum imap_envelope_field field,
			 enum imap_envelope_result_type result_type,
			 const char **result)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	int ret;

	i_assert(field < IMAP_ENVELOPE_FIELDS);

	input = i_stream_create_from_data(envelope, strlen(envelope));
	parser = imap_parser_create(input, NULL, (size_t)-1);

	(void)i_stream_read(input);
	ret = imap_parser_read_args(parser, field+1, 0, &args);
	if (ret > (int)field) {
		ret = imap_envelope_parse_arg(&args[field], field,
					      envelope, result_type, result);
	} else {
		i_error("Error parsing IMAP envelope: %s", envelope);
		*result = NULL;
		ret = FALSE;
	}

	imap_parser_destroy(&parser);
	i_stream_destroy(&input);
	return ret;
}
