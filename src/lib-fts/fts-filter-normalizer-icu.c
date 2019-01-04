/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h" /* unicode replacement char */
#include "fts-filter-common.h"
#include "fts-filter-private.h"
#include "fts-language.h"

#ifdef HAVE_LIBICU
#include "fts-icu.h"

struct fts_filter_normalizer_icu {
	struct fts_filter filter;
	pool_t pool;
	const char *transliterator_id;

	UTransliterator *transliterator;
	ARRAY_TYPE(icu_utf16) utf16_token, trans_token;
	string_t *utf8_token;
};

static void fts_filter_normalizer_icu_destroy(struct fts_filter *filter)
{
	struct fts_filter_normalizer_icu *np =
		(struct fts_filter_normalizer_icu *)filter;

	if (np->transliterator != NULL)
		utrans_close(np->transliterator);
	pool_unref(&np->pool);
}

static int
fts_filter_normalizer_icu_create(const struct fts_language *lang ATTR_UNUSED,
				 const char *const *settings,
				 struct fts_filter **filter_r,
				 const char **error_r)
{
	struct fts_filter_normalizer_icu *np;
	pool_t pp;
	unsigned int i, max_length = 250;
	const char *id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC; [\\x20] Remove";

	for (i = 0; settings[i] != NULL; i += 2) {
		const char *key = settings[i], *value = settings[i+1];

		if (strcmp(key, "id") == 0) {
			id = value;
		} else if (strcmp(key, "maxlen") == 0) {
			if (str_to_uint(value, &max_length) < 0 ||
			    max_length == 0) {
				*error_r = t_strdup_printf("Invalid icu maxlen setting: %s", value);
				return -1;
			}
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
	}

	pp = pool_alloconly_create(MEMPOOL_GROWING"fts_filter_normalizer_icu",
	                           sizeof(struct fts_filter_normalizer_icu));
	np = p_new(pp, struct fts_filter_normalizer_icu, 1);
	np->pool = pp;
	np->filter = *fts_filter_normalizer_icu;
	np->transliterator_id = p_strdup(pp, id);
	p_array_init(&np->utf16_token, pp, 64);
	p_array_init(&np->trans_token, pp, 64);
	np->utf8_token = buffer_create_dynamic(pp, 128);
	np->filter.max_length = max_length;
	*filter_r = &np->filter;
	return 0;
}

static int
fts_filter_normalizer_icu_filter(struct fts_filter *filter, const char **token,
				 const char **error_r)
{
	struct fts_filter_normalizer_icu *np =
		(struct fts_filter_normalizer_icu *)filter;

	if (np->transliterator == NULL)
		if (fts_icu_transliterator_create(np->transliterator_id,
		                                  &np->transliterator,
		                                  error_r) < 0)
			return -1;

	fts_icu_utf8_to_utf16(&np->utf16_token, *token);
	array_append_zero(&np->utf16_token);
	array_delete(&np->utf16_token, array_count(&np->utf16_token)-1, 1);
	array_clear(&np->trans_token);
	if (fts_icu_translate(&np->trans_token, array_first(&np->utf16_token),
			      array_count(&np->utf16_token),
			      np->transliterator, error_r) < 0)
		return -1;

	if (array_count(&np->trans_token) == 0)
		return 0;

	fts_icu_utf16_to_utf8(np->utf8_token, array_first(&np->trans_token),
			      array_count(&np->trans_token));
	fts_filter_truncate_token(np->utf8_token, np->filter.max_length);
	*token = str_c(np->utf8_token);
	return 1;
}

#else

static int
fts_filter_normalizer_icu_create(const struct fts_language *lang ATTR_UNUSED,
				 const char *const *settings ATTR_UNUSED,
				 struct fts_filter **filter_r ATTR_UNUSED,
				 const char **error_r)
{
	*error_r = "libicu support not built in";
	return -1;
}

static int
fts_filter_normalizer_icu_filter(struct fts_filter *filter ATTR_UNUSED,
				 const char **token ATTR_UNUSED,
				 const char **error_r ATTR_UNUSED)
{
	return -1;
}

static void
fts_filter_normalizer_icu_destroy(struct fts_filter *normalizer ATTR_UNUSED)
{
}

#endif

static const struct fts_filter fts_filter_normalizer_icu_real = {
	.class_name = "normalizer-icu",
	.v = {
		fts_filter_normalizer_icu_create,
		fts_filter_normalizer_icu_filter,
		fts_filter_normalizer_icu_destroy
	}
};

const struct fts_filter *fts_filter_normalizer_icu =
	&fts_filter_normalizer_icu_real;
