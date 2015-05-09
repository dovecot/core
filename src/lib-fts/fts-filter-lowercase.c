/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fts-filter.h"
#include "fts-filter-private.h"
#include "fts-language.h"

static void
fts_filter_lowercase_destroy(struct fts_filter *filter)
{
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

	*filter_r = filter;
	return 0;
}

static int
fts_filter_lowercase_filter(struct fts_filter *_filter ATTR_UNUSED,
			    const char **token,
			    const char **error_r ATTR_UNUSED)
{
	*token = t_str_lcase(*token);
	return 1;
}

static const struct fts_filter_vfuncs normalizer_filter_vfuncs = {
	fts_filter_lowercase_create,
	fts_filter_lowercase_filter,
	fts_filter_lowercase_destroy
};

static const struct fts_filter fts_filter_lowercase_real = {
	.class_name = "lowercase",
	.v = &normalizer_filter_vfuncs
};

const struct fts_filter *fts_filter_lowercase = &fts_filter_lowercase_real;
