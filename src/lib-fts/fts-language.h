#ifndef FTS_LANGUAGE_H
#define FTS_LANGUAGE_H

struct fts_language_list;

enum fts_language_result {
	/* Provided sample is too short. */
	FTS_LANGUAGE_RESULT_SHORT,
	/* Language is unknown or not in the provided list . */
	FTS_LANGUAGE_RESULT_UNKNOWN,

	FTS_LANGUAGE_RESULT_OK,
	/* textcat library initialization failed. */
	FTS_LANGUAGE_RESULT_ERROR
};

struct fts_language {
	/* Two-letter language name lowercased, e.g. "en" */
	const char *name;
};
ARRAY_DEFINE_TYPE(fts_language, const struct fts_language *);

/* Used for raw data that is indexed. This data shouldn't go through any
   language-specific filters. */
extern const struct fts_language fts_language_data;

/*
  Language module API.
*/
void fts_languages_init(void);
void fts_languages_deinit(void);
/* Add a language to the list of supported languages. */
void fts_language_register(const char *name);
/* Find a specified language by name. This finds from the internal list of
   supported languages. */
const struct fts_language *fts_language_find(const char *name);

/*
  Language list API
*/
int fts_language_list_init(const char *const *settings,
			   struct fts_language_list **list_r,
			   const char **error_r);
void fts_language_list_deinit(struct fts_language_list **list);

/* Add a language to the list of wanted languages. */
void fts_language_list_add(struct fts_language_list *list,
			   const struct fts_language *lang);
/* Add wanted languages from a space-separated list of language names.
   Duplicates are ignored. Returns TRUE if ok, FALSE and unknown_name if an
   unknown language was found from the list. */
bool fts_language_list_add_names(struct fts_language_list *list,
				 const char *names,
				 const char **unknown_name_r);

/* Return an array of all wanted languages. */
const ARRAY_TYPE(fts_language) *
fts_language_list_get_all(struct fts_language_list *list);
/* Returns the first wanted language (default language). */
const struct fts_language *
fts_language_list_get_first(struct fts_language_list *list);

/* If text was detected to be one of the languages in the list,
   returns FTS_LANGUAGE_RESULT_OK and (a pointer to) the language (in
   the list). */
enum fts_language_result
fts_language_detect(struct fts_language_list *list,
		    const unsigned char *text, size_t size,
                    const struct fts_language **lang_r);

#endif
