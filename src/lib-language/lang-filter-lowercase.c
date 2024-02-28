/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "language.h"
#include "lang-settings.h"
#include "lang-filter-private.h"

#ifdef HAVE_LIBICU
#  include "lang-icu.h"
#endif

static int
lang_filter_lowercase_create(const struct lang_settings *set ATTR_UNUSED,
			     struct event *event ATTR_UNUSED,
			     struct lang_filter **filter_r,
			     const char **error_r ATTR_UNUSED)
{
	struct lang_filter *filter;
	filter = i_new(struct lang_filter, 1);
	*filter = *lang_filter_lowercase;
	filter->token = str_new(default_pool, 64);

	*filter_r = filter;
	return 0;
}

static int
lang_filter_lowercase_filter(struct lang_filter *filter ATTR_UNUSED,
			     const char **token,
			     const char **error_r ATTR_UNUSED)
{
#ifdef HAVE_LIBICU
	str_truncate(filter->token, 0);
	lang_icu_lcase(filter->token, *token);
	*token = str_c(filter->token);
#else
	*token = t_str_lcase(*token);
#endif
	return 1;
}

static const struct lang_filter lang_filter_lowercase_real = {
	.class_name = "lowercase",
	.v = {
		lang_filter_lowercase_create,
		lang_filter_lowercase_filter,
		NULL
	}
};

const struct lang_filter *lang_filter_lowercase = &lang_filter_lowercase_real;
