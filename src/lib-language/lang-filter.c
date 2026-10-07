/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "module-dir.h"
#include "language.h"
#include "lang-filter-private.h"

#ifdef HAVE_LIBICU
#  include "lang-icu.h"
#endif

const char *lang_filter_module_dir = MODULE_DIR;

struct lang_filter_module_class {
	const char *module_name;
	const struct lang_filter *filter_class;
};

static ARRAY(const struct lang_filter *) lang_filter_classes;
static struct module *lang_filter_modules = NULL;
/* Filter classes registered by modules. This is freed when the last module
   unregisters. */
static ARRAY(struct lang_filter_module_class) lang_filter_module_classes;

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
	module_dir_unload(&lang_filter_modules);
	array_free(&lang_filter_classes);
}

static const struct lang_filter *
lang_filter_module_class_find(const char *module_name)
{
	const struct lang_filter_module_class *mclass;

	if (!array_is_created(&lang_filter_module_classes))
		return NULL;
	array_foreach(&lang_filter_module_classes, mclass) {
		if (strcmp(mclass->module_name, module_name) == 0)
			return mclass->filter_class;
	}
	return NULL;
}

void lang_filter_module_register(const char *module_name,
				 const struct lang_filter *filter_class)
{
	struct lang_filter_module_class *mclass;

	i_assert(lang_filter_module_class_find(module_name) == NULL);

	if (!array_is_created(&lang_filter_module_classes))
		i_array_init(&lang_filter_module_classes, 4);
	mclass = array_append_space(&lang_filter_module_classes);
	mclass->module_name = module_name;
	mclass->filter_class = filter_class;
}

void lang_filter_module_unregister(const char *module_name)
{
	const struct lang_filter_module_class *mclass;

	array_foreach(&lang_filter_module_classes, mclass) {
		if (strcmp(mclass->module_name, module_name) == 0) {
			array_delete(&lang_filter_module_classes,
				array_foreach_idx(&lang_filter_module_classes,
						  mclass), 1);
			if (array_is_empty(&lang_filter_module_classes))
				array_free(&lang_filter_module_classes);
			return;
		}
	}
	i_unreached();
}

int lang_filter_module_load(const char *module_name,
			    const struct lang_filter **class_r,
			    const char **error_r)
{
	const char *module_names[] = { module_name, NULL };
	struct module_dir_load_settings mod_set;
	struct module *module;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.setting_name = "<built-in lib-language lookup>";
	mod_set.require_init_funcs = TRUE;
	mod_set.ignore_missing = TRUE;
	if (module_dir_try_load_missing(&lang_filter_modules,
					lang_filter_module_dir, module_names,
					&mod_set, error_r) < 0)
		return -1;
	module = module_dir_find(lang_filter_modules, module_name);
	if (module == NULL)
		return 0;
	module_dir_init(lang_filter_modules);

	*class_r = lang_filter_module_class_find(module_name);
	if (*class_r == NULL) {
		*error_r = t_strdup_printf(
			"Module %s didn't register its filter class",
			module->path);
		return -1;
	}
	return 1;
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
