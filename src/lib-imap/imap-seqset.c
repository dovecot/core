/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-seqset.h"

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

static int
get_next_seq_range(const char **str, uint32_t *seq1_r, uint32_t *seq2_r)
{
	uint32_t seq1, seq2;

	if (**str == '*') {
		/* last message */
		seq1 = (uint32_t)-1;
		*str += 1;
	} else {
		seq1 = get_next_number(str);
		if (seq1 == 0)
			return -1;
	}

	if (**str != ':')
		seq2 = seq1;
	else {
		/* first:last range */
		*str += 1;

		if (**str == '*') {
			seq2 = (uint32_t)-1;
			*str += 1;
		} else {
			seq2 = get_next_number(str);
			if (seq2 == 0)
				return -1;
		}
	}

	if (seq1 > seq2) {
		/* swap, as specified by RFC-3501 */
		*seq1_r = seq2;
		*seq2_r = seq1;
	} else {
		*seq1_r = seq1;
		*seq2_r = seq2;
	}
	return 0;
}

int imap_seq_set_parse(const char *str, ARRAY_TYPE(seq_range) *dest)
{
	uint32_t seq1, seq2;

	while (*str != '\0') {
		if (get_next_seq_range(&str, &seq1, &seq2) < 0)
			return -1;
		seq_range_array_add_range(dest, seq1, seq2);

		if (*str == ',')
			str++;
		else if (*str != '\0')
			return -1;
	}
	return 0;
}

int imap_seq_set_nostar_parse(const char *str, ARRAY_TYPE(seq_range) *dest)
{
	if (imap_seq_set_parse(str, dest) < 0)
		return -1;

	if (seq_range_exists(dest, (uint32_t)-1)) {
		/* '*' used */
		return -1;
	}
	return 0;
}

int imap_seq_range_parse(const char *str, uint32_t *seq1_r, uint32_t *seq2_r)
{
	if (get_next_seq_range(&str, seq1_r, seq2_r) < 0)
		return -1;
	return *str == '\0' ? 0 : -1;
}
