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

typedef const char *settings_callback_t(const char *key, const char *value,
					void *context);

const char *
parse_setting_from_defs(pool_t pool, struct setting_def *defs, void *base,
			const char *key, const char *value);

void settings_read(const char *path, settings_callback_t *callback,
		   void *context);

#endif
