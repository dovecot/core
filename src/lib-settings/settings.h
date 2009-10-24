#ifndef SETTINGS_H
#define SETTINGS_H

enum setting_type {
	SET_STR,
	SET_INT,
	SET_BOOL
};

struct setting_def {
	enum setting_type type;
	const char *name;
	size_t offset;
};

#define DEF_STRUCT_STR(name, struct_name) \
	{ SET_STR + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, const char *), \
	  #name, offsetof(struct struct_name, name) }
#define DEF_STRUCT_INT(name, struct_name) \
	{ SET_INT + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, unsigned int), \
	  #name, offsetof(struct struct_name, name) }
#define DEF_STRUCT_BOOL(name, struct_name) \
	{ SET_BOOL + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, bool), \
	  #name, offsetof(struct struct_name, name) }

/* Return error message. When closing section, key = NULL, value = NULL. */
typedef const char *settings_callback_t(const char *key, const char *value,
					void *context);

/* Return TRUE if we want to go inside the section */
typedef bool settings_section_callback_t(const char *type, const char *name,
					 void *context, const char **errormsg);

extern settings_section_callback_t *null_settings_section_callback;

const char *
parse_setting_from_defs(pool_t pool, const struct setting_def *defs, void *base,
			const char *key, const char *value);

bool settings_read(const char *path, const char *section,
		   settings_callback_t *callback,
		   settings_section_callback_t *sect_callback, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define settings_read(path, section, callback, sect_callback, context) \
	({(void)(1 ? 0 : callback((const char *)0, (const char *)0, context)); \
	  (void)(1 ? 0 : sect_callback((const char *)0, (const char *)0, \
				       context, (const char **)0)); \
	  settings_read(path, section, (settings_callback_t *)callback, \
		(settings_section_callback_t *)sect_callback, context); })
#else
#  define settings_read(path, section, callback, sect_callback, context) \
	  settings_read(path, section, (settings_callback_t *)callback, \
		(settings_section_callback_t *)sect_callback, context)
#endif

#endif
