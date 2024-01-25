/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "language.h"

#ifdef HAVE_LIBEXTTEXTCAT_TEXTCAT_H
#  include <libexttextcat/textcat.h>
#elif defined (HAVE_LANG_EXTTEXTCAT)
#  include <textcat.h>
#endif

#ifndef TEXTCAT_RESULT_UNKNOWN /* old textcat.h has typos */
#  ifdef TEXTCAT_RESULT_UNKOWN
#    define TEXTCAT_RESULT_UNKNOWN TEXTCAT_RESULT_UNKOWN
#  endif
#endif

#define DETECT_STR_MAX_LEN 200

struct textcat {
	int refcount;
	void *handle;
	char *config_path, *data_dir, *failed;
};

struct language_list {
	pool_t pool;
	ARRAY_TYPE(language) languages;
	struct textcat *textcat;
	const char *textcat_config;
	const char *textcat_datadir;
};

pool_t languages_pool;
ARRAY_TYPE(language) languages;
#ifdef HAVE_LANG_EXTTEXTCAT
static struct textcat *textcat_cache = NULL;
#endif

/*  ISO 639-1 alpha 2 codes for languages */
const struct language languages_builtin [] = {
	{ "da" }, /* Danish */
	{ "de" }, /* German */
	{ "en" }, /* English */
	{ "es" }, /* Spanish */
	{ "fi" }, /* Finnish */
	{ "fr" }, /* French */
	{ "it" }, /* Italian */
	{ "nl" }, /* Dutch */
	{ "no" }, /* Both Bokmal and Nynorsk are detected as Norwegian */
	{ "pt" }, /* Portuguese */
	{ "ro" }, /* Romanian */
	{ "ru" }, /* Russian */
	{ "sv" }, /* Swedish */
	{ "tr" }, /* Turkish */
};

const struct language language_data = {
	LANGUAGE_DATA
};

#ifdef HAVE_LANG_EXTTEXTCAT
static void textcat_unref(struct textcat *textcat)
{
	i_assert(textcat->refcount > 0);
	if (--textcat->refcount > 0)
		return;

	if (textcat == textcat_cache)
		textcat_cache = NULL;

	i_free(textcat->config_path);
	i_free(textcat->data_dir);
	i_free(textcat->failed);
	if (textcat->handle != NULL)
		textcat_Done(textcat->handle);
	i_free(textcat);
}
#endif

void languages_init(void)
{
	unsigned int i;
	const struct language *lp;

	languages_pool = pool_alloconly_create("language",
	                                       sizeof(languages_builtin));
	p_array_init(&languages, languages_pool, N_ELEMENTS(languages_builtin));
	for (i = 0; i < N_ELEMENTS(languages_builtin); i++){
		lp = &languages_builtin[i];
		array_push_back(&languages, &lp);
	}
}

void languages_deinit(void)
{
#ifdef HAVE_LANG_EXTTEXTCAT
	if (textcat_cache != NULL)
		textcat_unref(textcat_cache);
#endif
	pool_unref(&languages_pool);
}

void language_register(const char *name)
{
	struct language *lang;

	if (language_find(name) != NULL)
		return;

	lang = p_new(languages_pool, struct language, 1);
	lang->name = p_strdup(languages_pool, name);
	array_push_back(&languages, (const struct language **)&lang);
}

const struct language *language_find(const char *name)
{
	const struct language *lang;

	array_foreach_elem(&languages, lang) {
		if (strcmp(lang->name, name) == 0)
			return lang;
	}
	return NULL;
}

struct language_list *language_list_init(const struct language_settings *settings)
{
	struct language_list *lp;
	pool_t pool;

	pool = pool_alloconly_create("language_list", 128);
	lp = p_new(pool, struct language_list, 1);
	lp->pool = pool;
	lp->textcat_config = p_strdup_empty(pool, settings->textcat_config_path);
	lp->textcat_datadir = p_strdup_empty(pool, settings->textcat_data_path);
	p_array_init(&lp->languages, pool, 32);
	return lp;
}

void language_list_deinit(struct language_list **list)
{
	struct language_list *lp = *list;

	*list = NULL;
#ifdef HAVE_LANG_EXTTEXTCAT
	if (lp->textcat != NULL)
		textcat_unref(lp->textcat);
#endif
	pool_unref(&lp->pool);
}

static const struct language *
language_list_find(struct language_list *list, const char *name)
{
	const struct language *lang;

	array_foreach_elem(&list->languages, lang) {
		if (strcmp(lang->name, name) == 0)
			return lang;
	}
	return NULL;
}

void language_list_add(struct language_list *list,
		       const struct language *lang)
{
	i_assert(language_list_find(list, lang->name) == NULL);
	array_push_back(&list->languages, &lang);
}

bool language_list_add_names(struct language_list *list,
			     const ARRAY_TYPE(lang_settings) *languages,
			     const char **unknown_name_r)
{
	struct lang_settings *entry;
	array_foreach_elem(languages, entry) {
		/* Data pseudo-language does not belong to the constructed list,
		   skip it. */
		if (strcmp(entry->name, LANGUAGE_DATA) == 0)
			continue;

		const struct language *lang = language_find(entry->name);
		if (lang == NULL) {
			/* unknown language */
			*unknown_name_r = entry->name;
			return FALSE;
		}
		if (language_list_find(list, lang->name) == NULL)
			language_list_add(list, lang);
	}
	return TRUE;
}

const ARRAY_TYPE(language) *
language_list_get_all(struct language_list *list)
{
	return &list->languages;
}

const struct language *
language_list_get_first(struct language_list *list)
{
	const struct language *const *langp;

	langp = array_front(&list->languages);
	return *langp;
}

#ifdef HAVE_LANG_EXTTEXTCAT
static bool language_match_lists(struct language_list *list,
                                 candidate_t *candp, int candp_len,
                                 const struct language **lang_r)
{
	const char *name;

	for (int i = 0; i < candp_len; i++) {
		/* name is <lang>-<optional country or characterset>-<encoding>
		   eg, fi--utf8 or pt-PT-utf8 */
		name = t_strcut(candp[i].name, '-');

		/* For Norwegian we treat both bokmal and nynorsk as "no". */
		if (strcmp(name, "nb") == 0 || strcmp(name, "nn") == 0)
			name = "no";
		if ((*lang_r = language_list_find(list, name)) != NULL)
			return TRUE;
	}
	return FALSE;
}
#endif

#ifdef HAVE_LANG_EXTTEXTCAT
static int language_textcat_init(struct language_list *list,
				 const char **error_r)
{
	const char *config_path;
	const char *data_dir;

	if (list->textcat != NULL) {
		if (list->textcat->failed != NULL) {
			*error_r = list->textcat->failed;
			return -1;
		}
		i_assert(list->textcat->handle != NULL);
		return 0;
	}

	config_path = list->textcat_config != NULL ? list->textcat_config :
		TEXTCAT_DATADIR"/fpdb.conf";
	data_dir = list->textcat_datadir != NULL ? list->textcat_datadir :
		TEXTCAT_DATADIR"/";
	if (textcat_cache != NULL) {
		if (strcmp(textcat_cache->config_path, config_path) == 0 &&
		    strcmp(textcat_cache->data_dir, data_dir) == 0) {
			list->textcat = textcat_cache;
			list->textcat->refcount++;
			return 0;
		}
		textcat_unref(textcat_cache);
	}

	textcat_cache = list->textcat = i_new(struct textcat, 1);
	textcat_cache->refcount = 2;
	textcat_cache->config_path = i_strdup(config_path);
	textcat_cache->data_dir = i_strdup(data_dir);
	textcat_cache->handle = special_textcat_Init(config_path, data_dir);
	if (textcat_cache->handle == NULL) {
		textcat_cache->failed = i_strdup_printf(
			"special_textcat_Init(%s, %s) failed",
			config_path, data_dir);
		*error_r = textcat_cache->failed;
		return -1;
	}
	/* The textcat minimum document size could be set here. It
	   currently defaults to 3. UTF8 is enabled by default. */
	return 0;
}
#endif

static enum language_detect_result
language_detect_textcat(struct language_list *list ATTR_UNUSED,
			const unsigned char *text ATTR_UNUSED,
			size_t size ATTR_UNUSED,
			const struct language **lang_r ATTR_UNUSED,
			const char **error_r ATTR_UNUSED)
{
#ifdef HAVE_LANG_EXTTEXTCAT
	candidate_t *candp; /* textcat candidate result array pointer */
	int cnt;
	bool match = FALSE;

	if (language_textcat_init(list, error_r) < 0)
		return LANGUAGE_DETECT_RESULT_ERROR;

	candp = textcat_GetClassifyFullOutput(list->textcat->handle);
	if (candp == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "textcat_GetCLassifyFullOutput failed: malloc() returned NULL");
	cnt = textcat_ClassifyFull(list->textcat->handle, (const void *)text,
				   I_MIN(size, DETECT_STR_MAX_LEN), candp);
	if (cnt > 0) {
		T_BEGIN {
			match = language_match_lists(list, candp, cnt, lang_r);
		} T_END;
		textcat_ReleaseClassifyFullOutput(list->textcat->handle, candp);
		if (match)
			return LANGUAGE_DETECT_RESULT_OK;
		else
			return LANGUAGE_DETECT_RESULT_UNKNOWN;
	} else {
		textcat_ReleaseClassifyFullOutput(list->textcat->handle, candp);
		switch (cnt) {
		case TEXTCAT_RESULT_SHORT:
			i_assert(size < DETECT_STR_MAX_LEN);
			return LANGUAGE_DETECT_RESULT_SHORT;
		case TEXTCAT_RESULT_UNKNOWN:
			return LANGUAGE_DETECT_RESULT_UNKNOWN;
		default:
			i_unreached();
		}
	}
#else
	return LANGUAGE_DETECT_RESULT_UNKNOWN;
#endif
}

enum language_detect_result
language_detect(struct language_list *list,
		const unsigned char *text ATTR_UNUSED,
		size_t size ATTR_UNUSED,
		const struct language **lang_r,
		const char **error_r)
{
	i_assert(array_count(&list->languages) > 0);

	/* if there's only a single wanted language, return it always. */
	if (array_count(&list->languages) == 1) {
		const struct language *const *langp =
			array_front(&list->languages);
		*lang_r = *langp;
		return LANGUAGE_DETECT_RESULT_OK;
	}
	return language_detect_textcat(list, text, size, lang_r, error_r);
}
