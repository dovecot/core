#ifndef SETTINGS_PARSER_H
#define SETTINGS_PARSER_H

#include "str-parse.h"

struct var_expand_table;
struct var_expand_func_table;

#define SETTINGS_SEPARATOR '/'
#define SETTINGS_SEPARATOR_S "/"

/* STR_VARS pointer begins with either of these initially. Before actually
   using the variables all variables in all unexpanded strings need to be
   expanded. Afterwards the string pointers should be increased to skip
   the initial '1' so it'll be easy to use them. */
#define SETTING_STRVAR_UNEXPANDED "0"
#define SETTING_STRVAR_EXPANDED "1"

enum setting_type {
	SET_BOOL,
	SET_UINT,
	SET_UINT_OCT,
	SET_TIME,
	SET_TIME_MSECS,
	SET_SIZE,
	SET_IN_PORT, /* internet port */
	SET_STR,
	SET_STR_VARS, /* string with %variables */
	SET_ENUM,
	SET_STRLIST, /* of type ARRAY_TYPE(const_string) */
	SET_ALIAS, /* alias name for above setting definition */
	SET_FILTER_NAME,
	SET_FILTER_ARRAY,
};
enum setting_flags {
	SET_FLAG_HIDDEN = BIT(0),
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
#define SETTING_DEFINE_STRUCT_STR_VARS(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STR_VARS, 0, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_ENUM(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_ENUM, 0, const char *, key, name, struct_name)

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
#define SETTING_DEFINE_STRUCT_STR_VARS_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_STR_VARS, SET_FLAG_HIDDEN, const char *, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_ENUM_HIDDEN(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_ENUM, SET_FLAG_HIDDEN, const char *, key, name, struct_name)

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

	bool (*check_func)(void *set, pool_t pool, const char **error_r);
	/* The event parameter can be used with settings_get*() to access other
	   settings structs. */
	bool (*ext_check_func)(struct event *event, void *set, pool_t pool, const char **error_r);
	bool (*expand_check_func)(void *set, pool_t pool, const char **error_r);

};
ARRAY_DEFINE_TYPE(setting_parser_info, struct setting_parser_info);

enum settings_parser_flags {
	SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS	= 0x01,
	SETTINGS_PARSER_FLAG_TRACK_CHANGES		= 0x02
};

struct setting_parser_context;

struct setting_parser_context *
settings_parser_init(pool_t set_pool, const struct setting_parser_info *root,
		     enum settings_parser_flags flags);
void settings_parser_ref(struct setting_parser_context *ctx);
void settings_parser_unref(struct setting_parser_context **ctx);

/* Returns the current settings. */
void *settings_parser_get_set(const struct setting_parser_context *ctx);
/* Return pointer to changes in the root setting structure. */
void *settings_parser_get_changes(struct setting_parser_context *ctx);

/* Return the last error. */
const char *settings_parser_get_error(struct setting_parser_context *ctx);

/* Returns pointer to value for a key, or NULL if not found. */
const void *
settings_parse_get_value(struct setting_parser_context *ctx,
			 const char **key, enum setting_type *type_r);
/* Set the change_counter to use for tracking the following changes.
   SETTINGS_PARSER_FLAG_TRACK_CHANGES must be enabled, and the counter must be
   higher than 0. If the same setting is changed multiple times with different
   change_counters, the highest change_counter is kept. */
void settings_parse_set_change_counter(struct setting_parser_context *ctx,
				       uint8_t change_counter);
/* Returns change_counter (>0) if setting has been changed by this parser. */
uint8_t settings_parse_get_change_counter(struct setting_parser_context *ctx,
					  const char *key);
/* Parse key/value pair. Returns 1 if OK, 0 if key is unknown, -1 if error. */
int settings_parse_keyvalue(struct setting_parser_context *ctx,
			    const char *key, const char *value);
/* Parse key index/value pair. The key_idx points to the key in
   info->defines[]. The key string is still needed to support strlists, which
   need the key in "strlist/key" format. Returns 0 if OK, -1 if error. */
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
/* Call all check_func()s and ext_check_func()s to see if currently parsed
   settings are valid. */
bool settings_parser_check(struct setting_parser_context *ctx, pool_t pool,
			   struct event *event, const char **error_r);
bool settings_check(struct event *event, const struct setting_parser_info *info,
		    pool_t pool, void *set, const char **error_r);

/* While parsing values, specifies if STR_VARS strings are already expanded. */
void settings_parse_set_expanded(struct setting_parser_context *ctx,
				 bool is_expanded);
/* Update variable string pointers to skip over the '1' or '0'.
   This is mainly useful when you want to run settings_parser_check() without
   actually knowing what the variables are. */
void settings_parse_var_skip(struct setting_parser_context *ctx);
void settings_var_skip(const struct setting_parser_info *info, void *set);
/* Expand all unexpanded variables using the given table. Update the string
   pointers so that they can be used without skipping over the '1'.
   Returns the same as var_expand(). */
int settings_var_expand(const struct setting_parser_info *info,
			void *set, pool_t pool,
			const struct var_expand_table *table,
			const char **error_r);
int settings_var_expand_with_funcs(const struct setting_parser_info *info,
				   void *set, pool_t pool,
				   const struct var_expand_table *table,
				   const struct var_expand_func_table *func_table,
				   void *func_context, const char **error_r);
/* Duplicate the entire setting parser. */
struct setting_parser_context *
settings_parser_dup(const struct setting_parser_context *old_ctx,
		    pool_t new_pool);

/* Return section name escaped */
const char *settings_section_escape(const char *name);
const char *settings_section_unescape(const char *name);

void set_config_binary(bool value);
bool is_config_binary(void);

#endif
