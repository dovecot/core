/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fts-icu.h"
#include "fts-language.h"
#include "fts-filter-private.h"

static void
fts_filter_lowercase_destroy(struct fts_filter *filter)
{
	str_free(&filter->token);
	i_free(filter);
}

static int
fts_filter_lowercase_create(const struct fts_language *lang ATTR_UNUSED,
			    const char *const *settings,
			    struct fts_filter **filter_r,
			    const char **error_r)
{
	struct fts_filter *filter;

	if (settings[0] != NULL) {
		*error_r = t_strdup_printf("Unknown setting: %s", settings[0]);
		return -1;
	}
	filter = i_new(struct fts_filter, 1);
	*filter = *fts_filter_lowercase;
	filter->token = str_new(default_pool, 64);

	*filter_r = filter;
	return 0;
}

static int
fts_filter_lowercase_filter(struct fts_filter *filter,
			    const char **token,
			    const char **error_r ATTR_UNUSED)
{
#ifdef HAVE_LIBICU
	str_truncate(filter->token, 0);
	fts_icu_lcase(filter->token, *token);
	*token = str_c(filter->token);
#else
	*token = t_str_lcase(*token);
#endif
	return 1;
}

static const struct fts_filter_vfuncs lowercase_filter_vfuncs = {
	fts_filter_lowercase_create,
	fts_filter_lowercase_filter,
	fts_filter_lowercase_destroy
};

static const struct fts_filter fts_filter_lowercase_real = {
	.class_name = "lowercase",
	.v = &lowercase_filter_vfuncs
};

const struct fts_filter *fts_filter_lowercase = &fts_filter_lowercase_real;
