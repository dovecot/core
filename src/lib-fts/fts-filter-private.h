#ifndef FTS_FILTER_PRIVATE_H
#define FTS_FILTER_PRIVATE_H

#define FTS_FILTER_CLASSES_NR 3

/*
 API that stemming providers (classes) must provide: The register()
 function is called when the class is registered via
 fts_filter_register() The create() function is called to get an
 instance of a registered filter class.  The destroy function is
 called to destroy an instance of a filter.

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
	const struct fts_filter_vfuncs *v;
	int refcount;
	struct fts_filter *parent;
};

#endif
