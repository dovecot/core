#ifndef FTS_FILTER_PRIVATE_H
#define FTS_FILTER_PRIVATE_H

#include "fts-filter.h"

#define FTS_FILTER_CLASSES_NR 6

/*
 API that stemming providers (classes) must provide: The create()
 function is called to get an instance of a registered filter class.
 The filter() function is called with tokens for the specific filter.
 The destroy function is called to destroy an instance of a filter.

*/
struct fts_filter_vfuncs {
	int (*create)(const struct fts_language *lang,
	              const char *const *settings,
	              struct fts_filter **filter_r,
	              const char **error_r);
	int (*filter)(struct fts_filter *filter, const char **token,
		      const char **error_r);

	void (*destroy)(struct fts_filter *filter);
};

struct fts_filter {
	const char *class_name; /* name of the class this is based on */
	struct fts_filter_vfuncs v;
	struct fts_filter *parent;
	string_t *token;
	size_t max_length;
	int refcount;
};

#endif
