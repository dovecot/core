/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-messageset.h"

static uint32_t get_next_number(const char **str)
{
	uint32_t num;

	num = 0;
	while (**str != '\0') {
		if (**str < '0' || **str > '9')
			break;

		num = num*10 + (**str - '0');
		(*str)++;
	}

	if (num == (uint32_t)-1) {
		/* FIXME: ugly hack, we're using this number to mean the
		   last existing message. In reality UIDs should never get
		   this high, so we can quite safely just drop this one down. */
		num--;
	}

	return num;
}

int imap_messageset_parse(ARRAY_TYPE(seq_range) *dest, const char *messageset)
{
	uint32_t seq1, seq2;

	while (*messageset != '\0') {
		if (*messageset == '*') {
			/* last message */
			seq1 = (uint32_t)-1;
			messageset++;
		} else {
			seq1 = get_next_number(&messageset);
			if (seq1 == 0)
				return -1;
		}

		if (*messageset != ':')
			seq2 = seq1;
		else {
			/* first:last range */
			messageset++;

			if (*messageset == '*') {
				seq2 = (uint32_t)-1;
				messageset++;
			} else {
				seq2 = get_next_number(&messageset);
				if (seq2 == 0)
					return -1;
			}
		}

		if (*messageset == ',')
			messageset++;
		else if (*messageset != '\0')
			return -1;

		if (seq1 > seq2) {
			/* swap, as specified by RFC-3501 */
			uint32_t temp = seq1;
			seq1 = seq2;
			seq2 = temp;
		}

		seq_range_array_add_range(dest, seq1, seq2);
	}
	return 0;
}
