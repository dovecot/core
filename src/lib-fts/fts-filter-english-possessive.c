/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "fts-common.h"
#include "fts-filter-private.h"

static unichar_t get_ending_utf8_char(const char *str, size_t *end_pos)
{
	unichar_t c;

	while (!UTF8_IS_START_SEQ(str[*end_pos])) {
		i_assert(*end_pos > 0);
		*end_pos -= 1;
	}
	if (uni_utf8_get_char(str + *end_pos, &c) <= 0)
		i_unreached();
	return c;
}

static int
fts_filter_english_possessive_filter(struct fts_filter *filter ATTR_UNUSED,
				     const char **token,
				     const char **error_r ATTR_UNUSED)
{
	size_t len = strlen(*token);
	unichar_t c;

	if (len > 1 && ((*token)[len-1] == 's' || (*token)[len-1] == 'S')) {
		len -= 2;
		c = get_ending_utf8_char(*token, &len);
		if (IS_APOSTROPHE(c))
			*token = t_strndup(*token, len);
	}
	return 1;
}

static const struct fts_filter fts_filter_english_possessive_real = {
	.class_name = "english-possessive",
	.v = {
		NULL,
		fts_filter_english_possessive_filter,
		NULL
	}
};

const struct fts_filter *fts_filter_english_possessive = &fts_filter_english_possessive_real;
