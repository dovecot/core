/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "temp-string.h"
#include "rfc822-address.h"
#include "imap-parser.h"
#include "imap-envelope.h"
#include "imap-quote.h"

struct _MessagePartEnvelopeData {
	Pool pool;

	char *date, *subject;
	Rfc822Address *from, *sender, *reply_to;
	Rfc822Address *to, *cc, *bcc;

	char *in_reply_to, *message_id;
};

static Rfc822Address *parse_address(Pool pool, const char *value,
				    size_t value_len)
{
	Rfc822Address *ret;

	t_push();
	ret = rfc822_address_parse(pool, t_strndup(value, value_len));
	t_pop();
	return ret;
}

void imap_envelope_parse_header(Pool pool, MessagePartEnvelopeData **data,
				const char *name,
				const char *value, size_t value_len)
{
	if (*data == NULL) {
		*data = p_new(pool, MessagePartEnvelopeData, 1);
		(*data)->pool = pool;
	}

	if (strcasecmp(name, "Date") == 0 && (*data)->date == NULL)
		(*data)->date = imap_quote_value(pool, value, value_len);
	else if (strcasecmp(name, "Subject") == 0 && (*data)->subject == NULL)
		(*data)->subject = imap_quote_value(pool, value, value_len);
	else if (strcasecmp(name, "From") == 0 && (*data)->from == NULL)
		(*data)->from = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Sender") == 0 && (*data)->sender == NULL)
		(*data)->sender = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Reply-To") == 0 && (*data)->reply_to == NULL)
		(*data)->reply_to = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "To") == 0 && (*data)->to == NULL)
		(*data)->to = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Cc") == 0 && (*data)->cc == NULL)
		(*data)->cc = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Bcc") == 0 && (*data)->bcc == NULL)
		(*data)->bcc = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "In-Reply-To") == 0 &&
		 (*data)->in_reply_to == NULL)
		(*data)->in_reply_to = imap_quote_value(pool, value, value_len);
	else if (strcasecmp(name, "Message-Id") == 0 &&
		 (*data)->message_id == NULL)
		(*data)->message_id = imap_quote_value(pool, value, value_len);
}

static void imap_write_address(TempString *str, Rfc822Address *addr)
{
	if (addr == NULL) {
		t_string_append(str, "NIL");
		return;
	}

	t_string_append_c(str, '(');
	while (addr != NULL) {
		t_string_append_c(str, '(');
		t_string_append(str, imap_quote_str_nil(addr->name));
		t_string_append_c(str, ' ');
		t_string_append(str, imap_quote_str_nil(addr->route));
		t_string_append_c(str, ' ');
		t_string_append(str, imap_quote_str_nil(addr->mailbox));
		t_string_append_c(str, ' ');
		t_string_append(str, imap_quote_str_nil(addr->domain));
		t_string_append_c(str, ')');

		addr = addr->next;
	}
	t_string_append_c(str, ')');
}

void imap_envelope_write_part_data(MessagePartEnvelopeData *data,
				   TempString *str)
{
	t_string_append(str, NVL(data->date, "NIL"));
	t_string_append_c(str, ' ');
	t_string_append(str, NVL(data->subject, "NIL"));

	t_string_append_c(str, ' ');
	imap_write_address(str, data->from);
	t_string_append_c(str, ' ');
	imap_write_address(str, NVL(data->sender, data->from));
	t_string_append_c(str, ' ');
	imap_write_address(str, NVL(data->reply_to, data->from));
	t_string_append_c(str, ' ');
	imap_write_address(str, data->to);
	t_string_append_c(str, ' ');
	imap_write_address(str, data->cc);
	t_string_append_c(str, ' ');
	imap_write_address(str, data->bcc);

	t_string_append_c(str, ' ');
	t_string_append(str, NVL(data->in_reply_to, "NIL"));
	t_string_append_c(str, ' ');
	t_string_append(str, NVL(data->message_id, "NIL"));
}

const char *imap_envelope_get_part_data(MessagePartEnvelopeData *data)
{
	TempString *str;

	str = t_string_new(2048);
        imap_envelope_write_part_data(data, str);
	return str->str;
}

static int imap_address_arg_append(ImapArg *arg, TempString *str, int *in_group)
{
	ImapArgList *list;
	const char *args[4];
	int i;

	if (arg->type != IMAP_ARG_LIST)
		return FALSE;
	list = arg->data.list;

	/* we require 4 arguments, strings or NILs */
	if (list->size < 4)
		return FALSE;

	for (i = 0; i < 4; i++) {
		if (list->args[i].type == IMAP_ARG_NIL)
			args[i] = NULL;
		else if (list->args[i].type == IMAP_ARG_STRING)
			args[i] = list->args[i].data.str;
		else
			return FALSE;
	}

	if (str->len > 0)
		t_string_append(str, ", ");

	if (*in_group) {
		if (args[0] == NULL && args[1] == NULL &&
		    args[2] == NULL && args[3] == NULL) {
			/* end of group */
			t_string_append_c(str, ';');
			*in_group = FALSE;
			return TRUE;
		}
	} else {
		if (args[0] == NULL && args[1] == NULL &&
		    args[2] != NULL && args[3] == NULL) {
			/* beginning of group */
			t_string_append(str, args[2]);
			t_string_append(str, ": ");
			*in_group = TRUE;
			return TRUE;
		}
	}

        /* name <@route:mailbox@domain> */
	if (args[0] != NULL) {
		t_string_append(str, args[0]);
		t_string_append_c(str, ' ');
	}

	t_string_append_c(str, '<');
	if (args[1] != NULL) {
		t_string_append_c(str, '@');
		t_string_append(str, args[1]);
		t_string_append_c(str, ':');
	}
	if (args[2] != NULL)
		t_string_append(str, args[2]);
	if (args[3] != NULL) {
		t_string_append_c(str, '@');
		t_string_append(str, args[3]);
	}
	t_string_append_c(str, '>');
	return TRUE;
}

static const char *imap_envelope_parse_address(ImapArg *arg)
{
	ImapArgList *list;
	TempString *str;
	size_t i;
	int in_group;

	if (arg->type != IMAP_ARG_LIST)
		return NULL;

	in_group = FALSE;
	str = t_string_new(128);

        list = arg->data.list;
	for (i = 0; i < list->size; i++) {
		if (!imap_address_arg_append(&list->args[i], str, &in_group))
			return NULL;
	}

	return str->str;
}

static const char *
imap_envelope_parse_arg(ImapArg *arg, ImapEnvelopeField field,
			const char *envelope)
{
	const char *value;

	if (arg->type == IMAP_ARG_NIL)
		return "";

	if (field >= IMAP_ENVELOPE_FROM && field <= IMAP_ENVELOPE_BCC)
		value = imap_envelope_parse_address(arg);
	else if (arg->type == IMAP_ARG_STRING || arg->type == IMAP_ARG_ATOM)
		value = t_strdup(arg->data.str);
	else
		value = NULL;

	if (value == NULL) {
		i_error("Invalid field %u in IMAP envelope: %s",
			field, envelope);
	}

	return value;
}

const char *imap_envelope_parse(const char *envelope, ImapEnvelopeField field)
{
	IBuffer *inbuf;
	ImapParser *parser;
	ImapArg *args;
	const char *value;
	int ret;

	i_assert(field < IMAP_ENVELOPE_FIELDS);

	inbuf = i_buffer_create_from_data(data_stack_pool, envelope,
					  strlen(envelope));
	parser = imap_parser_create(inbuf, NULL, 0);

	(void)i_buffer_read(inbuf);
	ret = imap_parser_read_args(parser, field+1, 0, &args);
	if (ret > (int)field) {
		value = imap_envelope_parse_arg(&args[field], field, envelope);
	} else {
		i_error("Error parsing IMAP envelope: %s", envelope);
		value = NULL;
	}

	imap_parser_destroy(parser);
	i_buffer_unref(inbuf);
	return value;
}
