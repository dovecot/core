/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-search.h"
#include "imap-search.h"
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

struct mail_search_seqset *
imap_messageset_parse(pool_t pool, const char *messageset)
{
        struct mail_search_seqset *ret, **next;
	uint32_t seq1, seq2;

	ret = NULL;
	next = &ret;

	while (*messageset != '\0') {
		if (*messageset == '*') {
			/* last message */
			seq1 = (uint32_t)-1;
			messageset++;
		} else {
			seq1 = get_next_number(&messageset);
			if (seq1 == 0)
				return NULL;
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
					return NULL;
			}
		}

		if (*messageset == ',')
			messageset++;
		else if (*messageset != '\0')
			return NULL;

		if (seq1 > seq2) {
			/* swap, as specified by RFC-3501 */
			uint32_t temp = seq1;
			seq1 = seq2;
			seq2 = temp;
		}

		*next = p_new(pool, struct mail_search_seqset, 1);
		(*next)->seq1 = seq1;
		(*next)->seq2 = seq2;
		next = &(*next)->next;
	}

	return ret;
}
