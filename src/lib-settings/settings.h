#ifndef __SETTINGS_H
#define __SETTINGS_H

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

/* Return error message. When closing section, key = NULL, value = NULL. */
typedef const char *settings_callback_t(const char *key, const char *value,
					void *context);

/* Return TRUE if we want to go inside the section */
typedef int settings_section_callback_t(const char *type, const char *name,
					void *context, const char **errormsg);

const char *
parse_setting_from_defs(pool_t pool, struct setting_def *defs, void *base,
			const char *key, const char *value);

int settings_read(const char *path, const char *section,
		  settings_callback_t *callback,
		  settings_section_callback_t *sect_callback, void *context);

#endif
