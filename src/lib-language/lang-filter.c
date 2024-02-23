/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "language.h"
#include "lang-filter-private.h"

#ifdef HAVE_LIBICU
#  include "lang-icu.h"
#endif

static ARRAY(const struct lang_filter *) lang_filter_classes;

void lang_filters_init(void)
{
	i_array_init(&lang_filter_classes, LANG_FILTER_CLASSES_NR);

	lang_filter_register(lang_filter_stopwords);
	lang_filter_register(lang_filter_stemmer_snowball);
	lang_filter_register(lang_filter_normalizer_icu);
	lang_filter_register(lang_filter_lowercase);
	lang_filter_register(lang_filter_english_possessive);
	lang_filter_register(lang_filter_contractions);
}

void lang_filters_deinit(void)
{
#ifdef HAVE_LIBICU
	lang_icu_deinit();
#endif
	array_free(&lang_filter_classes);
}

void lang_filter_register(const struct lang_filter *filter_class)
{
	i_assert(lang_filter_find(filter_class->class_name) == NULL);

	array_push_back(&lang_filter_classes, &filter_class);
}

const struct lang_filter *lang_filter_find(const char *name)
{
	const struct lang_filter *filter;

	array_foreach_elem(&lang_filter_classes, filter) {
		if (strcmp(filter->class_name, name) == 0)
			return filter;
	}
	return NULL;
}

int lang_filter_create(const struct lang_filter *filter_class,
                       struct lang_filter *parent,
                       const struct lang_settings *set,
		       struct event *event,
                       struct lang_filter **filter_r,
                       const char **error_r)
{
	struct lang_filter *fp;
	if (filter_class->v.create != NULL) {
		if (filter_class->v.create(set, event, &fp, error_r) < 0) {
			*filter_r = NULL;
			return -1;
		}
	} else {
		fp = i_new(struct lang_filter, 1);
		*fp = *filter_class;
	}
	fp->refcount = 1;
	fp->parent = parent;
	if (parent != NULL) {
		lang_filter_ref(parent);
	}
	*filter_r = fp;
	return 0;
}
void lang_filter_ref(struct lang_filter *fp)
{
	i_assert(fp->refcount > 0);

	fp->refcount++;
}

void lang_filter_unref(struct lang_filter **_fpp)
{
	struct lang_filter *fp = *_fpp;

	i_assert(fp->refcount > 0);
	*_fpp = NULL;

	if (--fp->refcount > 0)
		return;

	if (fp->parent != NULL)
		lang_filter_unref(&fp->parent);
	if (fp->v.destroy != NULL)
		fp->v.destroy(fp);
	else {
		/* default destroy implementation */
		str_free(&fp->token);
		i_free(fp);
	}
}

int lang_filter(struct lang_filter *filter, const char **token,
		const char **error_r)
{
	int ret = 0;

	i_assert((*token)[0] != '\0');

	/* Recurse to parent. */
	if (filter->parent != NULL)
		ret = lang_filter(filter->parent, token, error_r);

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
