/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "str.h"
#include "fts-filter.h"
#include "fts-filter-private.h"
#include "fts-language.h"

struct fts_filter_normalizer_simple {
	struct fts_filter filter;
	string_t *str;
};

static bool
fts_filter_normalizer_simple_supports(const struct fts_language *lang ATTR_UNUSED)
{
	return TRUE;
}

static void
fts_filter_normalizer_simple_destroy(struct fts_filter *_filter)
{
	struct fts_filter_normalizer_simple *filter =
		(struct fts_filter_normalizer_simple *)_filter;

	str_free(&filter->str);
	i_free(filter);
}

static int
fts_filter_normalizer_simple_create(const struct fts_language *lang ATTR_UNUSED,
				    const char *const *settings,
				    struct fts_filter **filter_r,
				    const char **error_r)
{
	struct fts_filter_normalizer_simple *filter;

	if (settings[0] != NULL) {
		*error_r = t_strdup_printf("Unknown setting: %s", settings[0]);
		return -1;
	}
	filter = i_new(struct fts_filter_normalizer_simple, 1);
	filter->filter = *fts_filter_normalizer_simple;
	filter->str = str_new(default_pool, 128);

	*filter_r = &filter->filter;
	return 0;
}

static int
fts_filter_normalizer_simple_filter(struct fts_filter *_filter,
				    const char **token,
				    const char **error_r ATTR_UNUSED)
{
	struct fts_filter_normalizer_simple *filter =
		(struct fts_filter_normalizer_simple *)_filter;

	str_truncate(filter->str, 0);
	if (uni_utf8_to_decomposed_titlecase(*token, strlen(*token),
					     filter->str) < 0)
		i_panic("fts-normalizer-simple: Token is not valid UTF-8: %s", *token);
	*token = str_c(filter->str);
	return 1;
}

static const struct fts_filter_vfuncs normalizer_filter_vfuncs = {
	fts_filter_normalizer_simple_supports,
	fts_filter_normalizer_simple_create,
	fts_filter_normalizer_simple_filter,
	fts_filter_normalizer_simple_destroy
};

static const struct fts_filter fts_filter_normalizer_simple_real = {
	.class_name = SIMPLE_NORMALIZER_FILTER_NAME,
	.v = &normalizer_filter_vfuncs
};

const struct fts_filter *fts_filter_normalizer_simple = &fts_filter_normalizer_simple_real;
