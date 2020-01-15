/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fts-language.h"
#include "fts-filter-private.h"
#include "fts-common.h"
#include "unichar.h"

static int
fts_filter_contractions_create(const struct fts_language *lang,
			       const char *const *settings,
			       struct fts_filter **filter_r,
			       const char **error_r)
{
	struct fts_filter *filter;

	if (settings[0] != NULL) {
		*error_r = t_strdup_printf("Unknown setting: %s", settings[0]);
		return -1;
	}
	if (strcmp(lang->name, "fr") != 0) {
		*error_r = t_strdup_printf("Unsupported language: %s", lang->name);
		return -1;
	}

	filter = i_new(struct fts_filter, 1);
	*filter = *fts_filter_contractions;
	filter->token = str_new(default_pool, 64);
	*filter_r = filter;
	return 0;
}

static int
fts_filter_contractions_filter(struct fts_filter *filter ATTR_UNUSED,
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

static const struct fts_filter fts_filter_contractions_real = {
	.class_name = "contractions",
	.v = {
		fts_filter_contractions_create,
		fts_filter_contractions_filter,
		NULL
	}
};

const struct fts_filter *fts_filter_contractions = &fts_filter_contractions_real;
