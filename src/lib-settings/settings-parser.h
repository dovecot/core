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
	SET_DEFLIST, /* of type array_t */
	SET_DEFLIST_UNIQUE,
	SET_STRLIST, /* of type ARRAY_TYPE(const_string) */
	SET_ALIAS /* alias name for above setting definition */
};
enum setting_flags {
	SET_FLAG_HIDDEN = BIT(0),
};
#define SETTING_TYPE_IS_DEFLIST(type) \
	((type) == SET_DEFLIST || (type) == SET_DEFLIST_UNIQUE)

#define SETTING_DEFINE_LIST_END { 0, 0, NULL, 0, NULL }

struct setting_define {
	enum setting_type type;
	enum setting_flags flags;
	const char *key;

	size_t offset;
	const struct setting_parser_info *list_info;
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

struct setting_parser_info {
	const char *module_name;
	const struct setting_define *defines;
	const void *defaults;

	size_t type_offset;
	size_t struct_size;

	size_t parent_offset;
	const struct setting_parser_info *parent;

	bool (*check_func)(void *set, pool_t pool, const char **error_r);
	bool (*expand_check_func)(void *set, pool_t pool, const char **error_r);
	const struct setting_parser_info *const *dependencies;

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
struct setting_parser_context *
settings_parser_init_list(pool_t set_pool,
			  const struct setting_parser_info *const *roots,
			  unsigned int count, enum settings_parser_flags flags);
void settings_parser_ref(struct setting_parser_context *ctx);
void settings_parser_unref(struct setting_parser_context **ctx);

/* Return pointer to root setting structure. */
void *settings_parser_get(struct setting_parser_context *ctx);
/* Returns settings for a specific root. The root is expected to exist, and it
   must be the same pointer as given to settings_parser_init*(). If it doesn't,
   the function panics. */
void *settings_parser_get_root_set(const struct setting_parser_context *ctx,
				   const struct setting_parser_info *root);
/* Combine settings_parser_get_root_set() and settings_dup(). */
void *settings_parser_get_root_set_dup(const struct setting_parser_context *ctx,
				       const struct setting_parser_info *root,
				       pool_t pool);
/* Like settings_parser_get(), but return change struct. */
void *settings_parser_get_changes(struct setting_parser_context *ctx);
/* Returns the setting parser's roots (same as given to init()). */
const struct setting_parser_info *const *
settings_parser_get_roots(const struct setting_parser_context *ctx);

/* Return the last error. */
const char *settings_parser_get_error(struct setting_parser_context *ctx);
/* Return the parser info used for the previously parsed line. */
const struct setting_parser_info *
settings_parse_get_prev_info(struct setting_parser_context *ctx);

/* Returns TRUE if the given key is a valid setting. */
bool settings_parse_is_valid_key(struct setting_parser_context *ctx,
				 const char *key);
/* If key is an alias, return the primary key name. If key exists, return key
   itself. If key doesn't exist, return NULL. */
const char *settings_parse_unalias(struct setting_parser_context *ctx,
				   const char *key);
/* Returns pointer to value for a key, or NULL if not found. */
const void *
settings_parse_get_value(struct setting_parser_context *ctx,
			 const char *key, enum setting_type *type_r);
/* Returns TRUE if setting has been changed by this parser. */
bool settings_parse_is_changed(struct setting_parser_context *ctx,
			       const char *key);
/* Parse a single line. Returns 1 if OK, 0 if key is unknown, -1 if error. */
int settings_parse_line(struct setting_parser_context *ctx, const char *line);
/* Parse key/value pair. Returns 1 if OK, 0 if key is unknown, -1 if error. */
int settings_parse_keyvalue(struct setting_parser_context *ctx,
			    const char *key, const char *value);
/* Call all check_func()s to see if currently parsed settings are valid. */
bool settings_parser_check(struct setting_parser_context *ctx, pool_t pool,
			   const char **error_r);
bool settings_check(const struct setting_parser_info *info, pool_t pool,
		    void *set, const char **error_r);

/* While parsing values, specifies if STR_VARS strings are already expanded. */
void settings_parse_set_expanded(struct setting_parser_context *ctx,
				 bool is_expanded);
/* Mark all the parsed settings with given keys as being already expanded. */
void settings_parse_set_key_expanded(struct setting_parser_context *ctx,
				     pool_t pool, const char *key);
void settings_parse_set_keys_expanded(struct setting_parser_context *ctx,
				      pool_t pool, const char *const *keys);
/* Update variable string pointers to skip over the '1' or '0'.
   This is mainly useful when you want to run settings_parser_check() without
   actually knowing what the variables are. */
void settings_parse_var_skip(struct setting_parser_context *ctx);
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
/* Duplicate the entire settings structure. */
void *settings_dup(const struct setting_parser_info *info,
		   const void *set, pool_t pool);
/* Same as settings_dup(), but assume that the old pointers can still be safely
   used. This saves memory since strings don't have to be duplicated. */
void *settings_dup_with_pointers(const struct setting_parser_info *info,
				 const void *set, pool_t pool);
/* Duplicate the entire setting parser. */
struct setting_parser_context *
settings_parser_dup(const struct setting_parser_context *old_ctx,
		    pool_t new_pool);

/* Copy changed settings from src to dest. If conflict_key_r is not NULL and
   both src and dest have changed the same setting, return -1 and set the
   key name. If it's NULL, the old setting is kept.

   KLUDGE: For SET_STRLIST types if both source and destination have identical
   keys, the duplicates in the source side are ignored. This is required to
   make the current config code work correctly. */
int settings_parser_apply_changes(struct setting_parser_context *dest,
				  const struct setting_parser_context *src,
				  pool_t pool, const char **conflict_key_r);

/* Return section name escaped */
const char *settings_section_escape(const char *name);

void set_config_binary(bool value);
bool is_config_binary(void);

#endif
