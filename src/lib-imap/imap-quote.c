/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "imap-quote.h"

void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len)
{
	size_t i;

	for (i = 0; i < value_len; i++) {
		if (value[i] == 0) {
			value_len = i;
			break;
		}

		if ((value[i] & 0x80) != 0)
			break;
	}

	if (i == value_len) {
		/* no 8bit chars, return as "string" */
		str_append_c(str, '"');
		str_append_n(str, value, value_len);
		str_append_c(str, '"');
	} else {
		/* return as literal */
		str_printfa(str, "{%"PRIuSIZE_T"}\r\n", value_len);
		str_append_n(str, value, value_len);
	}
}

const char *imap_quote_str_nil(const char *value)
{
	string_t *str;

	if (value == NULL)
		return "NIL";

	str = t_str_new(512);
	imap_quote_append(str, (const unsigned char *) value, (size_t)-1);
	return str_c(str);
}

char *imap_quote(pool_t pool, const unsigned char *value, size_t value_len)
{
	string_t *str;

	str = t_str_new(value_len + MAX_INT_STRLEN + 5);
	imap_quote_append(str, value, value_len);
	return p_strndup(pool, str_data(str), str_len(str));
}
