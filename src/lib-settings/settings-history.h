#ifndef SETTINGS_HISTORY_H
#define SETTINGS_HISTORY_H

struct setting_history_default {
	const char *key;
	const char *old_value;
	const char *version;
};

struct setting_history_rename {
	const char *old_key, *new_key;
	const char *version;
};

struct settings_history {
	ARRAY(struct setting_history_default) defaults;
	ARRAY(struct setting_history_rename) renames;
};

struct settings_history *settings_history_get(void);

/* Register new defaults/renames. The strings are assumed to be statically
   allocated, i.e. they are not duplicated. */
void settings_history_register_defaults(
	const struct setting_history_default *defaults, unsigned int count);
void settings_history_register_renames(
	const struct setting_history_rename *renames, unsigned int count);

#endif
