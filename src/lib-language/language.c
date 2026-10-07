/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "istream.h"
#include "write-full.h"
#include "safe-mkstemp.h"
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
/* Maximum number of textcat handles kept cached. Different users can have
   different language lists, and each list has its own handle. */
#define TEXTCAT_CACHE_MAX_COUNT 16

struct textcat {
	struct textcat *prev, *next;
	int refcount;
	void *handle;
	char *config_path, *data_dir, *languages, *failed;
};

struct language_list {
	pool_t pool;
	struct event *event;
	ARRAY_TYPE(language) languages;
	struct textcat *textcat;
	const char *textcat_config;
	const char *textcat_datadir;
	const char *temp_path_prefix;
	bool textcat_filter_languages;
};

pool_t languages_pool;
ARRAY_TYPE(language) languages;
#ifdef HAVE_LANG_EXTTEXTCAT
/* Most recently used first. Each cached textcat has a reference. */
static struct textcat *textcat_cache = NULL;
static unsigned int textcat_cache_count = 0;
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

	i_free(textcat->config_path);
	i_free(textcat->data_dir);
	i_free(textcat->languages);
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
	while (textcat_cache != NULL) {
		struct textcat *textcat = textcat_cache;

		DLLIST_REMOVE(&textcat_cache, textcat);
		textcat_unref(textcat);
	}
	textcat_cache_count = 0;
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

	i_assert(settings->temp_path_prefix != NULL);

	pool = pool_alloconly_create("language_list", 128);
	lp = p_new(pool, struct language_list, 1);
	lp->pool = pool;
	lp->event = event_create(settings->event);
	event_set_append_log_prefix(lp->event, "textcat: ");
	lp->textcat_config = p_strdup_empty(pool, settings->textcat_config_path);
	lp->textcat_datadir = p_strdup_empty(pool, settings->textcat_data_path);
	lp->temp_path_prefix = p_strdup(pool, settings->temp_path_prefix);
	lp->textcat_filter_languages = settings->textcat_filter_languages;
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
	event_unref(&lp->event);
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
static const char *language_textcat_name(const char *textcat_name)
{
	/* name is <lang>-<optional country or characterset>-<encoding>
	   eg, fi--utf8 or pt-PT-utf8 */
	const char *name = t_strcut(textcat_name, '-');

	/* For Norwegian we treat both bokmal and nynorsk as "no". */
	if (strcmp(name, "nb") == 0 || strcmp(name, "nn") == 0)
		name = "no";
	return name;
}

static bool language_match_lists(struct language_list *list,
                                 candidate_t *candp, int candp_len,
                                 const struct language **lang_r)
{
	const char *name;

	for (int i = 0; i < candp_len; i++) {
		name = language_textcat_name(candp[i].name);
		if ((*lang_r = language_list_find(list, name)) != NULL)
			return TRUE;
	}
	return FALSE;
}
#endif

#ifdef HAVE_LANG_EXTTEXTCAT
static const char *language_list_get_names_key(struct language_list *list)
{
	ARRAY_TYPE(const_string) names;
	const struct language *lang;

	t_array_init(&names, array_count(&list->languages));
	array_foreach_elem(&list->languages, lang)
		array_push_back(&names, &lang->name);
	array_sort(&names, i_strcmp_p);
	array_append_zero(&names);
	return t_strarray_join(array_front(&names), " ");
}

static int
language_textcat_write_config(struct language_list *list,
			      const string_t *config,
			      const char **path_r, const char **error_r)
{
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, list->temp_path_prefix);
	str_append(path, "textcat.");
	fd = safe_mkstemp_hostpid(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		*error_r = t_strdup_printf("safe_mkstemp(%s) failed: %m",
					   str_c(path));
		return -1;
	}
	if (write_full(fd, str_data(config), str_len(config)) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %m",
					   str_c(path));
		i_close_fd(&fd);
		i_unlink(str_c(path));
		return -1;
	}
	i_close_fd(&fd);
	*path_r = str_c(path);
	return 0;
}

/* Returns 1 if filtered config was written to filtered_path_r, 0 if the
   original config should be used as-is, -1 on error. */
static int
language_textcat_write_filtered_config(struct language_list *list,
				       const char *config_path,
				       const char **filtered_path_r,
				       const char **error_r)
{
	struct istream *input;
	const char *line;
	string_t *config;
	unsigned int total_count = 0, filtered_count = 0;
	int ret;

	/* Fingerprints for languages not in the wanted list could never be
	   returned as the detected language, but textcat still spends CPU
	   comparing the text against each of them. Write a new config
	   containing only the wanted languages' fingerprints. */
	config = str_new(default_pool, 1024);
	input = i_stream_create_file(config_path, IO_BLOCK_SIZE);
	while ((line = i_stream_read_next_line(input)) != NULL) T_BEGIN {
		/* <fingerprint file> <name> [# comment] */
		const char *const *args = t_strsplit_spaces(
			t_strcut(line, '#'), " \t");
		if (str_array_length(args) >= 2) {
			total_count++;
			const char *name = language_textcat_name(args[1]);
			if (language_list_find(list, name) != NULL) {
				str_append(config, line);
				str_append_c(config, '\n');
				filtered_count++;
			}
		}
	} T_END;
	if (input->stream_errno == ENOENT) {
		/* let textcat init fail with its own error */
		ret = 0;
	} else if (input->stream_errno != 0) {
		*error_r = t_strdup_printf(
			"Failed to read textcat config %s: %s",
			config_path, i_stream_get_error(input));
		ret = -1;
	} else if (filtered_count == 0 || filtered_count == total_count) {
		/* None of the wanted languages have fingerprints, or nothing
		   was filtered out. */
		ret = 0;
	} else {
		if (language_textcat_write_config(list, config,
						  filtered_path_r,
						  error_r) < 0) {
			ret = -1;
		} else {
			e_debug(list->event,
				"Using %u of %u fingerprints from %s",
				filtered_count, total_count, config_path);
			ret = 1;
		}
	}
	i_stream_unref(&input);
	str_free(&config);
	return ret;
}

static int language_textcat_init(struct language_list *list,
				 const char **error_r)
{
	struct textcat *textcat;
	const char *config_path;
	const char *data_dir;
	const char *languages;
	const char *filtered_path;
	int ret;

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
	languages = !list->textcat_filter_languages ? "" :
		language_list_get_names_key(list);
	for (textcat = textcat_cache; textcat != NULL;
	     textcat = textcat->next) {
		if (strcmp(textcat->config_path, config_path) == 0 &&
		    strcmp(textcat->data_dir, data_dir) == 0 &&
		    strcmp(textcat->languages, languages) == 0) {
			/* move to the head of the cache */
			DLLIST_REMOVE(&textcat_cache, textcat);
			DLLIST_PREPEND(&textcat_cache, textcat);
			list->textcat = textcat;
			list->textcat->refcount++;
			if (textcat->failed != NULL) {
				*error_r = textcat->failed;
				return -1;
			}
			return 0;
		}
	}

	if (textcat_cache_count >= TEXTCAT_CACHE_MAX_COUNT) {
		/* drop the least recently used */
		struct textcat *last = textcat_cache;
		while (last->next != NULL)
			last = last->next;
		DLLIST_REMOVE(&textcat_cache, last);
		textcat_unref(last);
		textcat_cache_count--;
	}

	textcat = list->textcat = i_new(struct textcat, 1);
	textcat->refcount = 2;
	textcat->config_path = i_strdup(config_path);
	textcat->data_dir = i_strdup(data_dir);
	textcat->languages = i_strdup(languages);
	DLLIST_PREPEND(&textcat_cache, textcat);
	textcat_cache_count++;

	ret = !list->textcat_filter_languages ? 0 :
		language_textcat_write_filtered_config(list, config_path,
						       &filtered_path, error_r);
	if (ret < 0) {
		textcat->failed = i_strdup(*error_r);
		*error_r = textcat->failed;
		return -1;
	}
	if (ret > 0) {
		/* textcat reads the config file and the fingerprints fully
		   during init, so the filtered config file can be deleted
		   immediately afterwards. */
		textcat->handle = special_textcat_Init(filtered_path, data_dir);
		i_unlink(filtered_path);
	} else {
		textcat->handle = special_textcat_Init(config_path, data_dir);
	}
	if (textcat->handle == NULL) {
		textcat->failed = i_strdup_printf(
			"special_textcat_Init(%s, %s) failed",
			config_path, data_dir);
		*error_r = textcat->failed;
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
