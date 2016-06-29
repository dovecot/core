#ifndef FTS_FILTER_H
#define FTS_FILTER_H

struct fts_language;
struct fts_filter;
/*
 Settings are given in the form of a const char * const *settings =
 {"key, "value", "key2", "value2", NULL} array of string pairs.
 The array has to be NULL terminated.
*/
/*
  Settings: "stopwords_dir", path to the directory containing stopword files.
  Stopword files are looked up in "<path>"/stopwords_<lang>.txt

 */
extern const struct fts_filter *fts_filter_stopwords;

/*
 Settings: "lang", language of the stemmed language.
 */
extern const struct fts_filter *fts_filter_stemmer_snowball;

/*
 Settings: "id", description of the normalizing/translitterating rules
 to use.  See
 http://userguide.icu-project.org/transforms/general#TOC-Transliterator-Identifiers
 for syntax. Defaults to "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC"

 "maxlen", maximum length of tokens that ICU normalizer will output.
  Defaults to 250.
 */
extern const struct fts_filter *fts_filter_normalizer_icu;

/* Lowecases the input. Supports UTF8, if libicu is available. */
extern const struct fts_filter *fts_filter_lowercase;

/* Removes <'s> suffix from words. */
extern const struct fts_filter *fts_filter_english_possessive;

/* Removes prefixing contractions from words. */
extern const struct fts_filter *fts_filter_contractions;

/* Register all built-in filters. */
void fts_filters_init(void);
void fts_filters_deinit(void);

/* Register a new class explicitly. Built-in classes are automatically
   registered. */
void fts_filter_register(const struct fts_filter *filter_class);

/*
 Filtering workflow, find --> create --> filter --> destroy.
 */
const struct fts_filter *fts_filter_find(const char *name);
int fts_filter_create(const struct fts_filter *filter_class,
                      struct fts_filter *parent,
                      const struct fts_language *lang,
                      const char *const *settings,
                      struct fts_filter **filter_r,
                      const char **error_r);
void fts_filter_ref(struct fts_filter *filter);
void fts_filter_unref(struct fts_filter **filter);

/* Returns 1 if token is returned in *token, 0 if token was filtered
   out (*token is also set to NULL) and -1 on error.
   Input is also given via *token.
*/
int fts_filter_filter(struct fts_filter *filter, const char **token,
		      const char **error_r);

#endif
