/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "imap-quote.h"

void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len)
{
	size_t i, linefeeds = 0;
	int literal = FALSE;

	if (value == NULL) {
		str_append(str, "NIL");
		return;
	}

	for (i = 0; i < value_len; i++) {
		if (value[i] == 0) {
			value_len = i;
			break;
		}

		if (value[i] == 13 || value[i] == 10)
                        linefeeds++;

		if ((value[i] & 0x80) != 0 ||
		    value[i] == '"' || value[i] == '\\')
			literal = TRUE;
	}

	if (!literal) {
		/* no 8bit chars or imapspecials, return as "string" */
		str_append_c(str, '"');
	} else {
		/* return as literal */
		str_printfa(str, "{%"PRIuSIZE_T"}\r\n", value_len - linefeeds);
	}

	if (linefeeds == 0)
		str_append_n(str, value, value_len);
	else {
		for (i = 0; i < value_len; i++) {
			if (value[i] != 13 && value[i] != 10)
				str_append_c(str, value[i]);
		}
	}

	if (!literal)
		str_append_c(str, '"');
}

char *imap_quote(pool_t pool, const unsigned char *value, size_t value_len)
{
	string_t *str;

	if (value == NULL)
		return "NIL";

	str = t_str_new(value_len + MAX_INT_STRLEN + 5);
	imap_quote_append(str, value, value_len);
	return p_strndup(pool, str_data(str), str_len(str));
}
