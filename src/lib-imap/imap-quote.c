/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-quote.h"

void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len, bool compress_lwsp)
{
	size_t i, extra = 0;
	bool last_lwsp = TRUE, literal = FALSE, modify = FALSE;

	if (value == NULL) {
		str_append(str, "NIL");
		return;
	}

	if (value_len == (size_t)-1)
		value_len = strlen((const char *) value);

	for (i = 0; i < value_len; i++) {
		switch (value[i]) {
		case 0:
			/* it's converted to 8bit char */
			literal = TRUE;
			modify = TRUE;
			last_lwsp = FALSE;
			break;
		case '\t':
			modify = TRUE;
			/* fall through */
		case ' ':
			if (last_lwsp && compress_lwsp) {
				modify = TRUE;
				extra++;
			}
			last_lwsp = TRUE;
			break;
		case 13:
		case 10:
			extra++;
			modify = TRUE;
			break;
		default:
			if ((value[i] & 0x80) != 0 ||
			    value[i] == '"' || value[i] == '\\')
				literal = TRUE;
			last_lwsp = FALSE;
		}
	}

	if (!literal) {
		/* no 8bit chars or imapspecials, return as "string" */
		str_append_c(str, '"');
	} else {
		/* return as literal */
		str_printfa(str, "{%"PRIuSIZE_T"}\r\n", value_len - extra);
	}

	if (!modify)
		str_append_n(str, value, value_len);
	else {
		last_lwsp = TRUE;
		for (i = 0; i < value_len; i++) {
			switch (value[i]) {
			case 0:
				str_append_c(str, 128);
				last_lwsp = FALSE;
				break;
			case ' ':
			case '\t':
				if (!last_lwsp || !compress_lwsp)
					str_append_c(str, ' ');
				last_lwsp = TRUE;
				break;
			case 13:
			case 10:
				break;
			default:
				last_lwsp = FALSE;
				str_append_c(str, value[i]);
				break;
			}
		}
	}

	if (!literal)
		str_append_c(str, '"');
}

const char *imap_quote(pool_t pool, const unsigned char *value,
		       size_t value_len)
{
	string_t *str;
	char *ret;

	if (value == NULL)
		return "NIL";

	if (!pool->datastack_pool)
		t_push();

	str = t_str_new(value_len + MAX_INT_STRLEN + 5);
	imap_quote_append(str, value, value_len, TRUE);
	ret = p_strndup(pool, str_data(str), str_len(str));

	if (!pool->datastack_pool)
		t_pop();
	return ret;
}
