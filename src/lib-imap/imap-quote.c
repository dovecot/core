/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "temp-string.h"
#include "imap-quote.h"

#define IS_BREAK_CHAR(c) \
	((c) == ' ' || (c) == '\t' || \
	 (c) == ',' || (c) == ':' || (c) == ';' || (c) == '@' || \
	 (c) == '<' || (c) == '>' || (c) == '(' || (c) == ')' || \
	 (c) == '[' || (c) == ']' || (c) == '=')

#define IS_BREAK_OR_CRLF_CHAR(c) \
	(IS_BREAK_CHAR(c) || (c) == '\r' || (c) == '\n')

static size_t next_token_quoted(const char *value, size_t len,
				int *need_qp, int *quoted)
{
	size_t i;

	*need_qp = FALSE;
	*quoted = TRUE;

	for (i = *quoted ? 0 : 1; i < len; i++) {
		if ((unsigned char)value[i] & 0x80)
			*need_qp = TRUE;

		if (value[i] == '"' || value[i] == '\r' || value[i] == '\n') {
			i++;
			*quoted = value[i] == '"';
			break;
		}
	}

	return i;
}

static size_t next_token(const char *value, size_t len,
			 int *need_qp, int *quoted, int qp_on)
{
	size_t i = 0;

	if (value[0] == '"' || *quoted)
		return next_token_quoted(value, len, need_qp, quoted);

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

	if (IS_BREAK_OR_CRLF_CHAR(value[i])) {
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

		if (IS_BREAK_OR_CRLF_CHAR(value[i]))
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
	int qp, need_qp, quoted;

	str = t_string_new(value_len * 2);
	qp = FALSE;
	quoted = FALSE;

	t_string_append_c(str, '"');
	while (value_len > 0) {
		token_len = next_token(value, value_len, &need_qp, &quoted, qp);
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

const char *imap_quote_str_nil(const char *value)
{
	return value == NULL ? "NIL" :
		get_quoted_str(value, strlen(value))->str;
}

char *imap_quote_value(Pool pool, const char *value, size_t value_len)
{
	TempString *str;

	str = get_quoted_str(value, value_len);
	return p_strndup(pool, str->str, str->len);
}
