#ifndef LANGUAGE_H
#define LANGUAGE_H

#include "lang-settings.h"

struct language_list;

enum language_detect_result {
	/* Provided sample is too short. */
	LANGUAGE_DETECT_RESULT_SHORT,
	/* Language is unknown or not in the provided list . */
	LANGUAGE_DETECT_RESULT_UNKNOWN,

	LANGUAGE_DETECT_RESULT_OK,
	/* textcat library initialization failed. */
	LANGUAGE_DETECT_RESULT_ERROR
};

struct language_settings {
	const char *textcat_config_path;
	const char *textcat_data_path;
};

struct language {
	/* Two-letter language name lowercased, e.g. "en" */
	const char *name;
};
ARRAY_DEFINE_TYPE(language, const struct language *);

/* Used for raw data that is indexed. This data shouldn't go through any
   language-specific filters. */
extern const struct language language_data;

/*
  Language module API.
*/
void languages_init(void);
void languages_deinit(void);
/* Add a language to the list of supported languages. */
void language_register(const char *name);
/* Find a specified language by name. This finds from the internal list of
   supported languages. */
const struct language *language_find(const char *name);

/*
  Language list API
*/
struct language_list *language_list_init(const struct language_settings *settings);
void language_list_deinit(struct language_list **list);

/* Add a language to the list of wanted languages. */
void language_list_add(struct language_list *list,
		       const struct language *lang);
/* Add wanted languages from a space-separated list of language names.
   Duplicates are ignored. Returns TRUE if ok, FALSE and unknown_name if an
   unknown language was found from the list. */
bool language_list_add_names(struct language_list *list,
			     const ARRAY_TYPE(lang_settings) *names,
			     const char **unknown_name_r);

/* Return an array of all wanted languages. */
const ARRAY_TYPE(language) * language_list_get_all(struct language_list *list);
/* Returns the first wanted language (default language). */
const struct language *
language_list_get_first(struct language_list *list);

/* If text was detected to be one of the languages in the list,
   returns LANGUAGE_RESULT_OK and (a pointer to) the language (in
   the list). error_r is set for LANGUAGE_RESULT_ERROR. */
enum language_detect_result
language_detect(struct language_list *list,
		const unsigned char *text, size_t size,
		const struct language **lang_r,
		const char **error_r);

#endif
