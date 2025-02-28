#ifndef LANG_FILTER_H
#define LANG_FILTER_H

struct language;
struct lang_filter;
struct lang_settings;

/*
 Settings are given in the form of a const char * const *settings =
 {"key, "value", "key2", "value2", NULL} array of string pairs.
 The array has to be NULL terminated.
*/
/*
  Settings: "stopwords_dir", path to the directory containing stopword files.
  Stopword files are looked up in "<path>"/stopwords_<lang>.txt

 */
extern const struct lang_filter *lang_filter_stopwords;

/*
 Settings: "lang", language of the stemmed language.
 */
extern const struct lang_filter *lang_filter_stemmer_snowball;

/*
 Settings: "id", description of the normalizing/transliterating rules
 to use.  See
 http://userguide.icu-project.org/transforms/general#TOC-Transliterator-Identifiers
 for syntax. Defaults to "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC"

 "maxlen", maximum length of tokens that ICU normalizer will output.
  Defaults to 250.
 */
extern const struct lang_filter *lang_filter_normalizer_icu;

/* Lowercases the input. Supports UTF8, if libicu is available. */
extern const struct lang_filter *lang_filter_lowercase;

/* Removes <'s> suffix from words. */
extern const struct lang_filter *lang_filter_english_possessive;

/* Removes prefixing contractions from words. */
extern const struct lang_filter *lang_filter_contractions;

/* Register all built-in filters. */
void lang_filters_init(void);
void lang_filters_deinit(void);

/* Register a new class explicitly. Built-in classes are automatically
   registered. */
void lang_filter_register(const struct lang_filter *filter_class);

/*
 Filtering workflow, find --> create --> filter --> destroy.
 */
const struct lang_filter *lang_filter_find(const char *name);
int lang_filter_create(const struct lang_filter *filter_class,
                       struct lang_filter *parent,
                       const struct lang_settings *set,
		       struct event *event,
                       struct lang_filter **filter_r,
                       const char **error_r);
void lang_filter_ref(struct lang_filter *filter);
void lang_filter_unref(struct lang_filter **filter);

/* Returns 1 if token is returned in *token, 0 if token was filtered
   out (*token is also set to NULL) and -1 on error.
   Input is also given via *token.
*/
int lang_filter(struct lang_filter *filter, const char **token,
		const char **error_r);

#endif
