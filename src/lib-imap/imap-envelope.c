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

#define IS_BREAK_CHAR(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n' || \
	 (c) == ',' || (c) == ':' || (c) == ';' || (c) == '@' || \
	 (c) == '<' || (c) == '>' || (c) == '(' || (c) == ')' || \
	 (c) == '[' || (c) == ']' || (c) == '=')

static size_t next_token_quoted(const char *value, size_t len, int *need_qp)
{
	size_t i;

	i_assert(value[0] == '"');

	*need_qp = FALSE;

	for (i = 1; i < len; i++) {
		if ((unsigned char)value[i] & 0x80)
			*need_qp = TRUE;

		if (value[i] == '"') {
			i++;
			break;
		}
	}

	return i;
}

static size_t next_token(const char *value, size_t len, int *need_qp, int qp_on)
{
	size_t i = 0;

	if (value[0] == '"')
		return next_token_quoted(value, len, need_qp);

	*need_qp = FALSE;

	if (qp_on) {
		/* skip spaces, so we don't end up QP'ing word at a time */
		for (i = 0; i < len; i++) {
			if (value[i] != ' ')
				break;
		}

		if (i == len)
			return i;
	}

	if (IS_BREAK_CHAR(value[i])) {
		/* return all break-chars in one token */
		for (i++; i < len; i++) {
			if (!IS_BREAK_CHAR(value[i]))
				break;
		}

		return i;
	}

	/* then stop at break-char */
	for (; i < len; i++) {
		if ((unsigned char)value[i] & 0x80)
			*need_qp = TRUE;

		if (IS_BREAK_CHAR(value[i]))
			break;
	}

	return i;
}

static void append_quoted_qp(TempString *str, const char *value, size_t len)
{
	size_t i;
	unsigned char c;

	/* do this the easy way, it's already broken behaviour to leave the
	   8bit text in mailbox, so we shouldn't need to try too hard to make
	   it readable. Keep 'A'..'Z', 'a'..'z' and '0'..'9', QP rest */

	for (i = 0; i < len; i++) {
		if (value[i] == ' ')
			t_string_append_c(str, '_');
		else if ((value[i] >= 'A' && value[i] <= 'Z') ||
			 (value[i] >= 'a' && value[i] <= 'z') ||
			 (value[i] >= '0' && value[i] <= '9')) {
			t_string_append_c(str, value[i]);
		} else {
			t_string_append_c(str, '=');
			c = (unsigned char)value[i] >> 4;
			t_string_append_c(str, c < 10 ? (c+'0') : (c-10+'A'));
			c = (unsigned char)value[i] & 0x0f;
			t_string_append_c(str, c < 10 ? (c+'0') : (c-10+'A'));
		}
	}
}

static void append_quoted(TempString *str, const char *value, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (value[i] == '\\' || value[i] == '"')
			t_string_append_c(str, '\\');
		t_string_append_c(str, value[i]);
	}
}

/* does two things: 1) escape '\' and '"' characters, 2) 8bit text -> QP */
static TempString *get_quoted_str(const char *value, size_t value_len)
{
	TempString *str;
	size_t token_len;
	int qp, need_qp;

	str = t_string_new(value_len * 2);
	qp = FALSE;

	t_string_append_c(str, '"');
	while (value_len > 0) {
		token_len = next_token(value, value_len, &need_qp, qp);
		i_assert(token_len > 0 && token_len <= value_len);

		/* header may be split to multiple lines, we don't want them */
		while (token_len > 0 && (value[0] == '\r' ||
					 value[0] == '\n')) {
			value++;
			token_len--;
			value_len--;
		}

		if (need_qp && !qp) {
			t_string_append(str, "=?x-unknown?Q?");
			qp = TRUE;
		} else if (!need_qp && qp) {
			t_string_append(str, "?=");
			qp = FALSE;
		}

		if (need_qp)
			append_quoted_qp(str, value, token_len);
		else
			append_quoted(str, value, token_len);

		value += token_len;
		value_len -= token_len;
	}

	if (qp) t_string_append(str, "?=");
	t_string_append_c(str, '"');

	return str;
}

static const char *quote_str_nil(const char *value)
{
	return value == NULL ? "NIL" :
		get_quoted_str(value, strlen(value))->str;
}

static char *quote_value(Pool pool, const char *value, size_t value_len)
{
	TempString *str;

	str = get_quoted_str(value, value_len);
	return p_strndup(pool, str->str, str->len);
}

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
