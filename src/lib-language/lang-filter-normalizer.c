/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "lang-filter-private.h"
#include "lang-settings.h"
#include "language.h"
#include "lang-filter-normalizer-icu.h"

/* The normalizer-icu filter is implemented by the
   lang_filter_normalizer_icu module, which uses libicu. The module is loaded
   only when the filter is created, so that the other processes don't need to
   load libicu. */
static int
lang_filter_normalizer_icu_create(const struct lang_settings *set,
				  struct event *event,
				  struct lang_filter **filter_r,
				  const char **error_r)
{
	const struct lang_filter *icu_class;
	int ret;

	ret = lang_filter_module_load(LANG_FILTER_NORMALIZER_ICU_MODULE_NAME,
				      &icu_class, error_r);
	if (ret == 0) {
		*error_r = t_strdup_printf(
			"language_filter_normalizer_icu_id '%s' requires libicu, "
			"but the "LANG_FILTER_NORMALIZER_ICU_MODULE_NAME
			" module isn't installed in %s",
			set->filter_normalizer_icu_id, lang_filter_module_dir);
		return -1;
	}
	if (ret < 0)
		return -1;
	return icu_class->v.create(set, event, filter_r, error_r);
}

static const struct lang_filter lang_filter_normalizer_icu_real = {
	.class_name = "normalizer-icu",
	.v = {
		lang_filter_normalizer_icu_create,
		NULL,
		NULL
	}
};

const struct lang_filter *lang_filter_normalizer_icu =
	&lang_filter_normalizer_icu_real;
