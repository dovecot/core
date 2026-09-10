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

/* A setting was replaced by another setting, whose value differs. Only the
   listed old value is migrated. */
struct setting_history_value {
	const char *old_key, *old_value;
	const char *new_key, *new_value;
	const char *version;
};

struct settings_history {
	ARRAY(struct setting_history_default) defaults;
	ARRAY(struct setting_history_rename) renames;
	ARRAY(struct setting_history_value) values;
	bool sort_pending;
};

struct settings_history *settings_history_get(void);

/* Register new defaults/renames. The strings are assumed to be statically
   allocated, i.e. they are not duplicated. */
void settings_history_register_defaults(
	const struct setting_history_default *defaults, unsigned int count);
void settings_history_register_renames(
	const struct setting_history_rename *renames, unsigned int count);
void settings_history_register_values(
	const struct setting_history_value *values, unsigned int count);

#endif
