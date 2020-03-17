/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fts-language.h"
#include "fts-filter-private.h"

#ifdef HAVE_FTS_STEMMER

#include <libstemmer.h>

struct fts_filter_stemmer_snowball {
	struct fts_filter filter;
	pool_t pool;
	struct fts_language *lang;
	struct sb_stemmer *stemmer;
};

static void fts_filter_stemmer_snowball_destroy(struct fts_filter *filter)
{
	struct fts_filter_stemmer_snowball *sp =
		(struct fts_filter_stemmer_snowball *)filter;

	if (sp->stemmer != NULL)
		sb_stemmer_delete(sp->stemmer);
	pool_unref(&sp->pool);
}

static int
fts_filter_stemmer_snowball_create(const struct fts_language *lang,
                                   const char *const *settings,
                                   struct fts_filter **filter_r,
                                   const char **error_r)
{
	struct fts_filter_stemmer_snowball *sp;
	pool_t pp;

	*filter_r = NULL;

	if (settings[0] != NULL) {
		*error_r = t_strdup_printf("Unknown setting: %s", settings[0]);
		return -1;
	}
	pp = pool_alloconly_create(MEMPOOL_GROWING"fts_filter_stemmer_snowball",
	                           sizeof(struct fts_filter));
	sp = p_new(pp, struct fts_filter_stemmer_snowball, 1);
	sp->pool = pp;
	sp->filter = *fts_filter_stemmer_snowball;
	sp->lang = p_malloc(sp->pool, sizeof(struct fts_language));
	sp->lang->name = p_strdup(sp->pool, lang->name);
	*filter_r = &sp->filter;
	return 0;
}

static int
fts_filter_stemmer_snowball_create_stemmer(struct fts_filter_stemmer_snowball *sp,
					   const char **error_r)
{
	sp->stemmer = sb_stemmer_new(sp->lang->name, "UTF_8");
	if (sp->stemmer == NULL) {
		*error_r = t_strdup_printf(
			"Creating a Snowball stemmer for language '%s' failed.",
			sp->lang->name);
		fts_filter_stemmer_snowball_destroy(&sp->filter);
		return -1;
	}
	return 0;
}

static int
fts_filter_stemmer_snowball_filter(struct fts_filter *filter,
                                   const char **token, const char **error_r)
{
	struct fts_filter_stemmer_snowball *sp =
		(struct fts_filter_stemmer_snowball *) filter;
	const sb_symbol *base;

	if (sp->stemmer == NULL) {
		if (fts_filter_stemmer_snowball_create_stemmer(sp, error_r) < 0)
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
	*token = t_strndup(base, sb_stemmer_length(sp->stemmer));
	return 1;
}

#else

static int
fts_filter_stemmer_snowball_create(const struct fts_language *lang ATTR_UNUSED,
                                   const char *const *settings ATTR_UNUSED,
                                   struct fts_filter **filter_r ATTR_UNUSED,
                                   const char **error_r)
{
	*error_r = "Snowball support not built in";
	return -1;
}
static void
fts_filter_stemmer_snowball_destroy(struct fts_filter *stemmer ATTR_UNUSED)
{
}

static int
fts_filter_stemmer_snowball_filter(struct fts_filter *filter ATTR_UNUSED,
				   const char **token ATTR_UNUSED,
				   const char **error_r ATTR_UNUSED)
{
	return -1;
}

#endif

static const struct fts_filter fts_filter_stemmer_snowball_real = {
	.class_name = "snowball",
	.v = {
		fts_filter_stemmer_snowball_create,
		fts_filter_stemmer_snowball_filter,
		fts_filter_stemmer_snowball_destroy
	}
};

const struct fts_filter *fts_filter_stemmer_snowball = &fts_filter_stemmer_snowball_real;
