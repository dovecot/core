/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "fts-language.h"
#include "fts-filter-private.h"

#ifdef HAVE_LIBICU
#  include "fts-icu.h"
#endif

static ARRAY(const struct fts_filter *) fts_filter_classes;

void fts_filters_init(void)
{
	i_array_init(&fts_filter_classes, FTS_FILTER_CLASSES_NR);

	fts_filter_register(fts_filter_stopwords);
	fts_filter_register(fts_filter_stemmer_snowball);
	fts_filter_register(fts_filter_normalizer_icu);
	fts_filter_register(fts_filter_lowercase);
	fts_filter_register(fts_filter_english_possessive);
	fts_filter_register(fts_filter_contractions);
}

void fts_filters_deinit(void)
{
#ifdef HAVE_LIBICU
	fts_icu_deinit();
#endif
	array_free(&fts_filter_classes);
}

void fts_filter_register(const struct fts_filter *filter_class)
{
	i_assert(fts_filter_find(filter_class->class_name) == NULL);

	array_push_back(&fts_filter_classes, &filter_class);
}

const struct fts_filter *fts_filter_find(const char *name)
{
	const struct fts_filter *const *fp = NULL;

	array_foreach(&fts_filter_classes, fp) {
		if (strcmp((*fp)->class_name, name) == 0)
			return *fp;
	}
	return NULL;
}

int fts_filter_create(const struct fts_filter *filter_class,
                      struct fts_filter *parent,
                      const struct fts_language *lang,
                      const char *const *settings,
                      struct fts_filter **filter_r,
                      const char **error_r)
{
	struct fts_filter *fp;
	const char *empty_settings = NULL;

	i_assert(settings == NULL || str_array_length(settings) % 2 == 0);

	if (settings == NULL)
		settings = &empty_settings;

	if (filter_class->v.create != NULL) {
		if (filter_class->v.create(lang, settings, &fp, error_r) < 0) {
			*filter_r = NULL;
			return -1;
		}
	} else {
		/* default implementation */
		if (settings[0] != NULL) {
			*error_r = t_strdup_printf("Unknown setting: %s", settings[0]);
			return -1;
		}
		fp = i_new(struct fts_filter, 1);
		*fp = *filter_class;
	}
	fp->refcount = 1;
	fp->parent = parent;
	if (parent != NULL) {
		fts_filter_ref(parent);
	}
	*filter_r = fp;
	return 0;
}
void fts_filter_ref(struct fts_filter *fp)
{
	i_assert(fp->refcount > 0);

	fp->refcount++;
}

void fts_filter_unref(struct fts_filter **_fpp)
{
	struct fts_filter *fp = *_fpp;

	i_assert(fp->refcount > 0);
	*_fpp = NULL;

	if (--fp->refcount > 0)
		return;

	if (fp->parent != NULL)
		fts_filter_unref(&fp->parent);
	if (fp->v.destroy != NULL)
		fp->v.destroy(fp);
	else {
		/* default destroy implementation */
		str_free(&fp->token);
		i_free(fp);
	}
}

int fts_filter_filter(struct fts_filter *filter, const char **token,
		      const char **error_r)
{
	int ret = 0;

	i_assert((*token)[0] != '\0');

	/* Recurse to parent. */
	if (filter->parent != NULL)
		ret = fts_filter_filter(filter->parent, token, error_r);

	/* Parent returned token or no parent. */
	if (ret > 0 || filter->parent == NULL)
		ret = filter->v.filter(filter, token, error_r);

	if (ret <= 0)
		*token = NULL;
	else {
		i_assert(*token != NULL);
		i_assert((*token)[0] != '\0');
	}
	return ret;
}
