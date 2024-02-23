/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "language.h"
#include "lang-filter-private.h"
#include "lang-common.h"
#include "lang-settings.h"
#include "unichar.h"

static int
lang_filter_contractions_create(const struct lang_settings *set,
				struct event *event ATTR_UNUSED,
			        struct lang_filter **filter_r,
			        const char **error_r)
{
	struct lang_filter *filter;

	if (strcmp(set->name, "fr") != 0) {
		*error_r = t_strdup_printf("Unsupported language: %s", set->name);
		return -1;
	}

	filter = i_new(struct lang_filter, 1);
	*filter = *lang_filter_contractions;
	filter->token = str_new(default_pool, 64);
	*filter_r = filter;
	return 0;
}

static int
lang_filter_contractions_filter(struct lang_filter *filter ATTR_UNUSED,
			    const char **_token,
			    const char **error_r ATTR_UNUSED)
{
	int char_size, pos = 0;
	unichar_t apostrophe;
	const char *token = *_token;

	switch (token[pos]) {
	case 'q':
		pos++;
		if (token[pos] == '\0' || token[pos] != 'u')
			break;
		/* fall through */
	case 'c':
	case 'd':
	case 'j':
	case 'l':
	case 'm':
	case 'n':
	case 's':
	case 't':
		pos++;
		if (token[pos] == '\0')
			break;
		char_size = uni_utf8_get_char(token + pos, &apostrophe);
		i_assert(char_size > 0);
		if (IS_APOSTROPHE(apostrophe)) {
			pos += char_size;
			*_token = token + pos;
		}
		if (token[pos] == '\0') /* nothing left */
			return 0;
		break;
	default:
		/* do nothing */
		break;
	}

	return 1;
}

static const struct lang_filter lang_filter_contractions_real = {
	.class_name = "contractions",
	.v = {
		lang_filter_contractions_create,
		lang_filter_contractions_filter,
		NULL
	}
};

const struct lang_filter *lang_filter_contractions = &lang_filter_contractions_real;
