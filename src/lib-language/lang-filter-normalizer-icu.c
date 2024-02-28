/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h" /* unicode replacement char */
#include "lang-filter-private.h"
#include "lang-settings.h"
#include "language.h"

#ifdef HAVE_LIBICU
#include "lang-icu.h"

struct lang_filter_normalizer_icu {
	struct lang_filter filter;
	pool_t pool;
	const char *transliterator_id;

	UTransliterator *transliterator;
	ARRAY_TYPE(icu_utf16) utf16_token, trans_token;
	string_t *utf8_token;
};

static void lang_filter_normalizer_icu_destroy(struct lang_filter *filter)
{
	struct lang_filter_normalizer_icu *np =
		(struct lang_filter_normalizer_icu *)filter;

	if (np->transliterator != NULL)
		utrans_close(np->transliterator);
	pool_unref(&np->pool);
}

static int
lang_filter_normalizer_icu_create(const struct lang_settings *set,
				  struct event *event ATTR_UNUSED,
				  struct lang_filter **filter_r,
				  const char **error_r ATTR_UNUSED)
{
	struct lang_filter_normalizer_icu *np;
	pool_t pp;

	pp = pool_alloconly_create(MEMPOOL_GROWING"lang_filter_normalizer_icu",
	                           sizeof(struct lang_filter_normalizer_icu));
	np = p_new(pp, struct lang_filter_normalizer_icu, 1);
	np->pool = pp;
	np->filter = *lang_filter_normalizer_icu;
	np->transliterator_id = set->filter_normalizer_icu_id;
	p_array_init(&np->utf16_token, pp, 64);
	p_array_init(&np->trans_token, pp, 64);
	np->utf8_token = buffer_create_dynamic(pp, 128);
	*filter_r = &np->filter;
	return 0;
}

static int
lang_filter_normalizer_icu_filter(struct lang_filter *filter, const char **token,
				 const char **error_r)
{
	struct lang_filter_normalizer_icu *np =
		(struct lang_filter_normalizer_icu *)filter;

	if (np->transliterator == NULL)
		if (lang_icu_transliterator_create(np->transliterator_id,
		                                   &np->transliterator,
		                                   error_r) < 0)
			return -1;

	lang_icu_utf8_to_utf16(&np->utf16_token, *token);
	array_append_zero(&np->utf16_token);
	array_pop_back(&np->utf16_token);
	array_clear(&np->trans_token);
	if (lang_icu_translate(&np->trans_token, array_front(&np->utf16_token),
			       array_count(&np->utf16_token),
			       np->transliterator, error_r) < 0)
		return -1;

	if (array_count(&np->trans_token) == 0)
		return 0;

	lang_icu_utf16_to_utf8(np->utf8_token, array_front(&np->trans_token),
			      array_count(&np->trans_token));
	*token = str_c(np->utf8_token);
	return 1;
}

#else

static int
lang_filter_normalizer_icu_create(const struct lang_settings *set ATTR_UNUSED,
				  struct event *event ATTR_UNUSED,
				  struct lang_filter **filter_r ATTR_UNUSED,
				  const char **error_r)
{
	*error_r = "libicu support not built in";
	return -1;
}

static int
lang_filter_normalizer_icu_filter(struct lang_filter *filter ATTR_UNUSED,
				  const char **token ATTR_UNUSED,
				  const char **error_r ATTR_UNUSED)
{
	return -1;
}

static void
lang_filter_normalizer_icu_destroy(struct lang_filter *normalizer ATTR_UNUSED)
{
}

#endif

static const struct lang_filter lang_filter_normalizer_icu_real = {
	.class_name = "normalizer-icu",
	.v = {
		lang_filter_normalizer_icu_create,
		lang_filter_normalizer_icu_filter,
		lang_filter_normalizer_icu_destroy
	}
};

const struct lang_filter *lang_filter_normalizer_icu =
	&lang_filter_normalizer_icu_real;
