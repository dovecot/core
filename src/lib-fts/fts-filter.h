#ifndef FTS_FILTER_H
#define FTS_FILTER_H
#include "array.h"

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
#define STOPWORDS_FILTER_NAME "stopwords"

/*
 Settings: "lang", language of the stemmed language.
 */
extern const struct fts_filter *fts_filter_stemmer_snowball;
#define SNOWBALL_STEMMER_FILTER_NAME "snowball"

/*
 Settings: "id", description of the normalizing/translitterating rules
 to use.  See
 http://userguide.icu-project.org/transforms/general#TOC-Transliterator-Identifiers
 for syntax.  Defaults to "Any-Lower; NFKD; [: Nonspacing Mark :]
 Remove; NFC"
 */
extern const struct fts_filter *fts_filter_normalizer_icu;
#define ICU_NORMALIZER_FILTER_NAME "normalizer-icu"

/* Normalization using i;unicode-casemap (RFC 5051) */
extern const struct fts_filter *fts_filter_normalizer_simple;
#define SIMPLE_NORMALIZER_FILTER_NAME "normalizer-simple"

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

/* Returns the filtered token or NULL, if it was completely removed */
const char *
fts_filter_filter(struct fts_filter *filter, const char *token);

#endif
