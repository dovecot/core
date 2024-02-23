/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "language.h"
#include "lang-filter-private.h"
#include "lang-settings.h"

#ifdef HAVE_LANG_STEMMER

#include <libstemmer.h>

struct lang_filter_stemmer_snowball {
	struct lang_filter filter;
	pool_t pool;
	struct language *lang;
	struct sb_stemmer *stemmer;
};

static void lang_filter_stemmer_snowball_destroy(struct lang_filter *filter)
{
	struct lang_filter_stemmer_snowball *sp =
		(struct lang_filter_stemmer_snowball *)filter;

	if (sp->stemmer != NULL)
		sb_stemmer_delete(sp->stemmer);
	pool_unref(&sp->pool);
}

static int
lang_filter_stemmer_snowball_create(const struct lang_settings *set,
				    struct event *event ATTR_UNUSED,
                                    struct lang_filter **filter_r,
                                    const char **error_r ATTR_UNUSED)
{
	struct lang_filter_stemmer_snowball *sp;
	pool_t pp;

	pp = pool_alloconly_create(MEMPOOL_GROWING"lang_filter_stemmer_snowball",
	                           sizeof(struct lang_filter));
	sp = p_new(pp, struct lang_filter_stemmer_snowball, 1);
	sp->pool = pp;
	sp->filter = *lang_filter_stemmer_snowball;
	sp->lang = p_malloc(sp->pool, sizeof(struct language));
	sp->lang->name = p_strdup(sp->pool, set->name);
	*filter_r = &sp->filter;
	return 0;
}

static int
lang_filter_stemmer_snowball_create_stemmer(struct lang_filter_stemmer_snowball *sp,
					    const char **error_r)
{
	sp->stemmer = sb_stemmer_new(sp->lang->name, "UTF_8");
	if (sp->stemmer == NULL) {
		*error_r = t_strdup_printf(
			"Creating a Snowball stemmer for language '%s' failed.",
			sp->lang->name);
		lang_filter_stemmer_snowball_destroy(&sp->filter);
		return -1;
	}
	return 0;
}

static int
lang_filter_stemmer_snowball_filter(struct lang_filter *filter,
                                    const char **token, const char **error_r)
{
	struct lang_filter_stemmer_snowball *sp =
		(struct lang_filter_stemmer_snowball *) filter;
	const sb_symbol *base;

	if (sp->stemmer == NULL) {
		if (lang_filter_stemmer_snowball_create_stemmer(sp, error_r) < 0)
			return -1;
	}

	base = sb_stemmer_stem(sp->stemmer, (const unsigned char *)*token, strlen(*token));
	if (base == NULL) {
		/* the only reason why this could fail is because of
		   out of memory. */
		i_fatal_status(FATAL_OUTOFMEM,
			       "sb_stemmer_stem(len=%zu) failed: Out of memory",
			       strlen(*token));
	}
	int len = sb_stemmer_length(sp->stemmer);
	if (len > 0)
		*token = t_strndup(base, len);
	else {
		/* If the stemmer returns an empty token, the return value
		 * should be 0 instead of 1 (otherwise it causes an assertion
		 * fault in lang_filter() ).
		 * However, removing tokens may bring the same kind of issues
		 * and inconsistencies that stopwords cause when used with
		 * multiple languages and negations.
		 * So, when the stemmer asks to remove a token,
		 * keep the original token unchanged instead. */
	}
	return 1;
}

#else

static int
lang_filter_stemmer_snowball_create(const struct lang_settings *set ATTR_UNUSED,
				    struct event *event ATTR_UNUSED,
                                    struct lang_filter **filter_r ATTR_UNUSED,
                                    const char **error_r)
{
	*error_r = "Snowball support not built in";
	return -1;
}
static void
lang_filter_stemmer_snowball_destroy(struct lang_filter *stemmer ATTR_UNUSED)
{
}

static int
lang_filter_stemmer_snowball_filter(struct lang_filter *filter ATTR_UNUSED,
				    const char **token ATTR_UNUSED,
				    const char **error_r ATTR_UNUSED)
{
	return -1;
}

#endif

static const struct lang_filter lang_filter_stemmer_snowball_real = {
	.class_name = "snowball",
	.v = {
		lang_filter_stemmer_snowball_create,
		lang_filter_stemmer_snowball_filter,
		lang_filter_stemmer_snowball_destroy
	}
};

const struct lang_filter *lang_filter_stemmer_snowball = &lang_filter_stemmer_snowball_real;
