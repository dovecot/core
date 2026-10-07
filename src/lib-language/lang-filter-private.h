#ifndef LANG_FILTER_PRIVATE_H
#define LANG_FILTER_PRIVATE_H

#include "lang-filter.h"

#define LANG_FILTER_CLASSES_NR 6

struct lang_settings;

/*
 API that stemming providers (classes) must provide: The create()
 function is called to get an instance of a registered filter class.
 The filter() function is called with tokens for the specific filter.
 The destroy function is called to destroy an instance of a filter.

*/
struct lang_filter_vfuncs {
	int (*create)(const struct lang_settings *set,
		      struct event *event,
	              struct lang_filter **filter_r,
	              const char **error_r);
	int (*filter)(struct lang_filter *filter, const char **token,
		      const char **error_r);

	void (*destroy)(struct lang_filter *filter);
};

struct lang_filter {
	const char *class_name; /* name of the class this is based on */
	struct lang_filter_vfuncs v;
	struct lang_filter *parent;
	string_t *token;
	int refcount;
};

/* Directory where filter modules are loaded from. Defaults to MODULE_DIR. */
extern const char *lang_filter_module_dir;

/* Load filter class implementation from the given module. The module's init
   function must register the class with lang_filter_module_register().
   The module stays loaded until lang_filters_deinit(). Returns 1 if loaded,
   0 if the module isn't installed, -1 on error. */
int lang_filter_module_load(const char *module_name,
			    const struct lang_filter **class_r,
			    const char **error_r);
/* Register/unregister filter class implemented by the module. These are
   called by the module's init and deinit functions. */
void lang_filter_module_register(const char *module_name,
				 const struct lang_filter *filter_class);
void lang_filter_module_unregister(const char *module_name);

#endif
