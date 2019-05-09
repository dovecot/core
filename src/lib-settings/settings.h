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

bool settings_read_i(const char *path, const char *section,
		     settings_callback_t *callback,
		     settings_section_callback_t *sect_callback, void *context,
		     const char **error_r)
	ATTR_NULL(2, 4, 5);
#define settings_read(path, section, callback, sect_callback, context, error_r) \
	  settings_read_i(path - \
		CALLBACK_TYPECHECK(callback, const char *(*)( \
			const char *, const char *, typeof(context))) - \
		CALLBACK_TYPECHECK(sect_callback, bool (*)( \
			const char *, const char *, typeof(context), \
			const char **)), \
		section, (settings_callback_t *)callback, \
		(settings_section_callback_t *)sect_callback, context, error_r)
#define settings_read_nosection(path, callback, context, error_r) \
	  settings_read_i(path - \
		CALLBACK_TYPECHECK(callback, const char *(*)( \
			const char *, const char *, typeof(context))), \
		NULL, (settings_callback_t *)callback, NULL, context, error_r)

#endif
