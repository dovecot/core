/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "temp-string.h"
#include "rfc822-address.h"
#include "imap-envelope.h"

struct _MessagePartEnvelopeData {
	Pool pool;

	char *date, *subject;
	Rfc822Address *from, *sender, *reply_to;
	Rfc822Address *to, *cc, *bcc;

	char *in_reply_to, *message_id;
};

static const char *
t_buffer_get_quote(const char *value, unsigned int *value_len)
{
	char *buf, *p;
	unsigned int i, len;

	len = *value_len;
	p = buf = t_buffer_get(len * 2 + 3);
	*p++ = '"';
	for (i = 0; i < len; i++) {
		if (value[i] == '\\' || value[i] == '"')
			*p++ = '\\';
		*p++ = value[i];
	}
	*p++ = '"';
	*p++ = '\0';

	*value_len = (unsigned int) (p-buf);
	return buf;
}

static const char *quote_str_nil(const char *value)
{
	const char *buf;
	unsigned int value_len;

	if (value == NULL)
		return "NIL";

	value_len = strlen(value);
	buf = t_buffer_get_quote(value, &value_len);
	t_buffer_alloc(value_len);
	return buf;
}

static char *quote_value(Pool pool, const char *value, unsigned int value_len)
{
	const char *buf;

	buf = t_buffer_get_quote(value, &value_len);
	return p_strndup(pool, buf, value_len);
}

static Rfc822Address *parse_address(Pool pool, const char *value,
				    unsigned int value_len)
{
	Rfc822Address *ret;

	t_push();
	ret = rfc822_address_parse(pool, t_strndup(value, value_len));
	t_pop();
	return ret;
}

void imap_envelope_parse_header(Pool pool, MessagePartEnvelopeData **data,
				const char *name,
				const char *value, unsigned int value_len)
{
	if (*data == NULL) {
		*data = p_new(pool, MessagePartEnvelopeData, 1);
		(*data)->pool = pool;
	}

	if (strcasecmp(name, "Date") == 0)
		(*data)->date = quote_value(pool, value, value_len);
	else if (strcasecmp(name, "Subject") == 0)
		(*data)->subject = quote_value(pool, value, value_len);
	else if (strcasecmp(name, "From") == 0)
		(*data)->from = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Sender") == 0)
		(*data)->sender = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Reply-To") == 0)
		(*data)->reply_to = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "To") == 0)
		(*data)->to = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Cc") == 0)
		(*data)->cc = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "Bcc") == 0)
		(*data)->bcc = parse_address(pool, value, value_len);
	else if (strcasecmp(name, "In-Reply-To") == 0)
		(*data)->in_reply_to = quote_value(pool, value, value_len);
	else if (strcasecmp(name, "Message-Id") == 0)
		(*data)->message_id = quote_value(pool, value, value_len);
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
		t_string_append(str, quote_str_nil(addr->name));
		t_string_append_c(str, ' ');
		t_string_append(str, quote_str_nil(addr->route));
		t_string_append_c(str, ' ');
		t_string_append(str, quote_str_nil(addr->mailbox));
		t_string_append_c(str, ' ');
		t_string_append(str, quote_str_nil(addr->domain));
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
