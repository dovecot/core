#ifndef SETTINGS_PARSER_H
#define SETTINGS_PARSER_H

#include "str-parse.h"

struct var_expand_table;
struct var_expand_func_table;

#define SETTINGS_SEPARATOR '/'
#define SETTINGS_SEPARATOR_S "/"

/* These values are shown as "unlimited" */
#define SET_VALUE_UNLIMITED "unlimited"
#define SET_UINT_UNLIMITED UINT_MAX
#define SET_SIZE_UNLIMITED UOFF_T_MAX

/* These values are shown as "infinite" */
#define SET_VALUE_INFINITE "infinite"
#define SET_TIME_INFINITE UINT_MAX
#define SET_TIME_MSECS_INFINITE UINT_MAX

enum setting_type {
	SET_BOOL,
	SET_UINT,
	SET_UINT_OCT,
	SET_TIME,
	SET_TIME_MSECS,
	SET_SIZE,
	SET_IN_PORT, /* internet port */
	SET_STR, /* string with %variables */
	SET_STR_NOVARS, /* string explicitly without %variables */
	SET_ENUM,
	SET_STRLIST, /* of type ARRAY_TYPE(const_string) */
	SET_BOOLLIST, /* of type ARRAY_TYPE(const_string) - guaranteed NULL-terminted */
	SET_ALIAS, /* alias name for above setting definition */
	SET_FILTER_NAME,
	SET_FILTER_HIERARCHY,
	SET_FILTER_ARRAY,
};
enum setting_flags {
	SET_FLAG_HIDDEN = BIT(0),
};

enum setting_apply_flags {
	/* Used when applying override settings (e.g. userdb or -o parameter) */
	SETTING_APPLY_FLAG_OVERRIDE = BIT(0),
	/* SETTINGS_GET_FLAG_NO_EXPAND is being used. */
	SETTING_APPLY_FLAG_NO_EXPAND = BIT(1),
};

#define SETTING_DEFINE_LIST_END { 0, 0, NULL, 0, NULL, NULL }

struct setting_define {
	enum setting_type type;
	enum setting_flags flags;
	const char *key;

	size_t offset;
	const char *filter_array_field_name;
	const char *required_setting;
};

#define SETTING_DEFINE_STRUCT_TYPE(_enum_type, _flags, _c_type, _key, _name, _struct_name) \
	{ .type = (_enum_type) + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((_struct_name *)0)->_name, _c_type), \
	  .flags = _flags, .key = _key, \
	  .offset = offsetof(_struct_name, _name) }

#define SETTING_DEFINE_STRUCT_BOOL(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_BOOL, 0, bool, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_UINT(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_UINT, 0, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_UINT_OCT(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_UINT_OCT, 0, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_TIME(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_TIME, 0, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_TIME_MSECS(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_TIME_MSECS, 0, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_SIZE(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_SIZE, 0, uoff_t, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_IN_PORT(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_IN_PORT, 0, in_port_t, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_STR(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STR, 0, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_STR_NOVARS(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STR_NOVARS, 0, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_ENUM(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_ENUM, 0, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_BOOLLIST(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_BOOLLIST, 0, ARRAY_TYPE(const_string), key, name, struct_name)
#define SETTING_DEFINE_STRUCT_STRLIST(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STRLIST, 0, ARRAY_TYPE(const_string), key, name, struct_name)

#define SETTING_DEFINE_STRUCT_BOOL_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_BOOL, SET_FLAG_HIDDEN, bool, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_UINT_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_UINT, SET_FLAG_HIDDEN, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_UINT_OCT_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_UINT_OCT, SET_FLAG_HIDDEN, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_TIME_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_TIME, SET_FLAG_HIDDEN, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_TIME_MSECS_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_TIME_MSECS, SET_FLAG_HIDDEN, unsigned int, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_SIZE_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_SIZE, SET_FLAG_HIDDEN, uoff_t, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_IN_PORT_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_IN_PORT, SET_FLAG_HIDDEN, in_port_t, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_STR_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STR, SET_FLAG_HIDDEN, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_STR_NOVARS_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STR_NOVARS, SET_FLAG_HIDDEN, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_ENUM_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_ENUM, SET_FLAG_HIDDEN, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_BOOLLIST_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_BOOLLIST, SET_FLAG_HIDDEN, ARRAY_TYPE(const_string), key, name, struct_name)
#define SETTING_DEFINE_STRUCT_STRLIST_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STRLIST, SET_FLAG_HIDDEN, ARRAY_TYPE(const_string), key, name, struct_name)

struct setting_keyvalue {
	const char *key;
	const char *value;
};

struct setting_parser_info {
	/* Unique name for the settings struct */
	const char *name;

	const struct setting_define *defines;
	const void *defaults;
	/* Add defaults via strings on top of the of defaults struct. */
	const struct setting_keyvalue *default_settings;

	size_t struct_size;
	size_t pool_offset1; /* 1 + offset to pool_t field */

	/* This is called for every setting that is parsed. *value is already
	   the final pointer stored into the settings struct. If it's modified,
	   it should usually be allocated from set->pool. */
	bool (*setting_apply)(struct event *event, void *set,
			      const char *key, const char **value,
			      enum setting_apply_flags flags, const char **error_r);
	/* This is called after %variable expansion. */
	bool (*check_func)(void *set, pool_t pool, const char **error_r);
	/* The event parameter can be used with settings_get*() to access other
	   settings structs. */
	bool (*ext_check_func)(struct event *event, void *set, pool_t pool, const char **error_r);

};
ARRAY_DEFINE_TYPE(setting_parser_info, struct setting_parser_info);

enum settings_parser_flags {
	SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS	= 0x01,
	/* Filters are added in reverse order. New filters are inserted to the
	   beginning of the array. */
	SETTINGS_PARSER_FLAG_INSERT_FILTERS		= 0x04,
};

struct setting_parser_context;

/* If a string setting value has this pointer, it means the setting isn't
   actually known because it contained %{variables}. [ext_]check_func() can use
   this to not give early errors when the variable value isn't known. */
extern const char *set_value_unknown;

struct setting_parser_context *
settings_parser_init(pool_t set_pool, const struct setting_parser_info *root,
		     enum settings_parser_flags flags);
void settings_parser_ref(struct setting_parser_context *ctx);
void settings_parser_unref(struct setting_parser_context **ctx);

/* Returns number of defines in info->defines */
unsigned int
setting_parser_info_get_define_count(const struct setting_parser_info *info);
/* Find a specific key from info and return its index number in the defines
   array. "list/key" will return the list's define. If the key is an
   alias, the primary key's index is returned. */
bool setting_parser_info_find_key(const struct setting_parser_info *info,
				  const char *key, unsigned int *idx_r);

/* Returns the current settings. */
void *settings_parser_get_set(const struct setting_parser_context *ctx);

/* Return the last error. */
const char *settings_parser_get_error(struct setting_parser_context *ctx);

/* Returns pointer to value for a key, or NULL if not found. */
const void *
settings_parse_get_value(struct setting_parser_context *ctx,
			 const char **key, enum setting_type *type_r);
/* Parse key/value pair. Returns 1 if OK, 0 if key is unknown, -1 if error. */
int settings_parse_keyvalue(struct setting_parser_context *ctx,
			    const char *key, const char *value);
/* Parse key index/value pair. The key_idx points to the key in
   info->defines[]. The key string is still needed to support lists, which
   need the key in "list/key" format. Returns 0 if OK, -1 if error. */
int settings_parse_keyidx_value(struct setting_parser_context *ctx,
				unsigned int key_idx, const char *key,
				const char *value);
/* Same as settings_parse_keyvalue(), but don't strdup() the value. The value
   pointer's validity must be enforced by the caller. */
int settings_parse_keyvalue_nodup(struct setting_parser_context *ctx,
				  const char *key, const char *value);
/* Same as settings_parse_keyidx_value(), but don't strdup() the value.
   The value pointer's validity must be enforced by the caller. */
int settings_parse_keyidx_value_nodup(struct setting_parser_context *ctx,
				      unsigned int key_idx, const char *key,
				      const char *value);
/* Returns TRUE if list has the specific key. The key must NOT include the
   list/ prefix. */
bool settings_parse_list_has_key(struct setting_parser_context *ctx,
				 unsigned int key_idx,
				 const char *key_suffix);
/* Call all check_func()s and ext_check_func()s to see if currently parsed
   settings are valid. */
bool settings_parser_check(struct setting_parser_context *ctx, pool_t pool,
			   struct event *event, const char **error_r);
bool settings_check(struct event *event, const struct setting_parser_info *info,
		    pool_t pool, void *set, const char **error_r);

int settings_parse_boollist_string(const char *value, pool_t pool,
				   ARRAY_TYPE(const_string) *dest,
				   const char **error_r);
/* Returns the boollist array NULL-terminated. The list is actually always
   already NULL-terminated, but to avoid confusion with regular non-NULL
   terminated arrays, use this function instead. Also, it includes some sanity
   checks to try to make sure it's used only for boollists. */
const char *const *settings_boollist_get(const ARRAY_TYPE(const_string) *array);

/* Return section name escaped */
const char *settings_section_escape(const char *name);
const char *settings_section_unescape(const char *name);

static inline bool settings_value_is_unlimited(const char *value)
{
	/* allow both as input for all types */
	return strcmp(value, SET_VALUE_UNLIMITED) == 0 ||
		strcmp(value, SET_VALUE_INFINITE) == 0;
}

void set_config_binary(bool value);
bool is_config_binary(void);

#endif
