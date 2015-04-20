/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fts-language.h"
#include "fts-filter.h"
#include "fts-filter-private.h"

#ifdef HAVE_FTS_STEMMER

#include <libstemmer.h>

struct fts_filter_stemmer_snowball {
	struct fts_filter filter;
	struct sb_stemmer *stemmer;
};

static bool
fts_filter_stemmer_snowball_supports(const struct fts_language *lang)
{
	struct sb_stemmer  *stemmer = sb_stemmer_new(t_str_lcase(lang->name),
	                                             NULL);
	if (stemmer != NULL) {
		sb_stemmer_delete(stemmer);
		return TRUE;
	}
	return FALSE;
}

static void fts_filter_stemmer_snowball_destroy(struct fts_filter *filter)
{
	struct fts_filter_stemmer_snowball *sp =
		(struct fts_filter_stemmer_snowball *)filter;

	if (sp->stemmer != NULL)
		sb_stemmer_delete(sp->stemmer);
	i_free(sp);
}

static int
fts_filter_stemmer_snowball_create(const struct fts_language *lang,
                                   const char *const *settings,
                                   struct fts_filter **filter_r,
                                   const char **error_r)
{
	struct fts_filter_stemmer_snowball *sp;

	*filter_r = NULL;

	if (settings[0] != NULL) {
		*error_r = t_strdup_printf("Unknown setting: %s", settings[0]);
		return -1;
	}

	sp = i_new(struct fts_filter_stemmer_snowball, 1);
	sp->filter = *fts_filter_stemmer_snowball;
	sp->stemmer = sb_stemmer_new(t_str_lcase(lang->name), NULL);
	if (sp->stemmer == NULL) {
		if (error_r != NULL) {
			*error_r = t_strdup_printf("Creating a Snowball stemmer failed." \
			                    " lang: %s", lang->name);
		}
		fts_filter_stemmer_snowball_destroy(&sp->filter);
		return -1;
	}
	*filter_r = &sp->filter;
	return 0;
}

static const char *
fts_filter_stemmer_snowball_filter(struct fts_filter *filter,
                                   const char *token)
{
	const sb_symbol *base;
	int len;
	struct fts_filter_stemmer_snowball *sp =
		(struct fts_filter_stemmer_snowball *) filter;

	base = sb_stemmer_stem(sp->stemmer, (const unsigned char *)token, strlen(token));
	len = sb_stemmer_length(sp->stemmer);
	return t_strdup_until(base, base + len);
}

#else

static bool
fts_filter_stemmer_snowball_supports(const struct fts_language *lang ATTR_UNUSED)
{
	return FALSE;
}
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

static const char *
fts_filter_stemmer_snowball_filter(struct fts_filter *filter ATTR_UNUSED,
                                   const char *token ATTR_UNUSED)
{
	return NULL;
}

#endif
static const struct fts_filter_vfuncs snowball_stemmer_filter_vfuncs = {
	fts_filter_stemmer_snowball_supports,
	fts_filter_stemmer_snowball_create,
	fts_filter_stemmer_snowball_filter,
	fts_filter_stemmer_snowball_destroy
};

static const struct fts_filter fts_filter_stemmer_snowball_real = {
	.class_name = SNOWBALL_STEMMER_FILTER_NAME,
	.v = &snowball_stemmer_filter_vfuncs
};

const struct fts_filter *fts_filter_stemmer_snowball = &fts_filter_stemmer_snowball_real;
