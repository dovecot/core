#ifndef SETTINGS_H
#define SETTINGS_H

#include "var-expand.h"
#include "settings-parser.h"

struct settings_root;
struct settings_mmap;
struct settings_instance;
struct var_expand_params;

enum settings_override_type {
	/* Setting is a built-in default. This is used only when the defaults
	   aren't coming from configuration (e.g. -O parameter or with unit
	   tests). */
	SETTINGS_OVERRIDE_TYPE_DEFAULT,
	/* Setting is from userdb. */
	SETTINGS_OVERRIDE_TYPE_USERDB,
	/* Setting is from -o command line parameters. */
	SETTINGS_OVERRIDE_TYPE_CLI_PARAM,
	/* Built-in default for a "2nd setting group". For example these are
	   used by "doveadm import" to specify the import storage source
	   settings. */
	SETTINGS_OVERRIDE_TYPE_2ND_DEFAULT,
	/* This is intended to be used by a separate CLI parameter specific to
	   the "2nd setting group". It overrides the 2ND_DEFAULT settings,
	   or any other settings as well. */
	SETTINGS_OVERRIDE_TYPE_2ND_CLI_PARAM,
	/* Setting is hardcoded to be overridden in the code. */
	SETTINGS_OVERRIDE_TYPE_CODE,

	SETTINGS_OVERRIDE_TYPE_COUNT,
};

enum settings_read_flags {
	/* Don't drop filters that contain a mismatching protocol */
	SETTINGS_READ_NO_PROTOCOL_FILTER = BIT(0),
	/* Check that all the paths referenced by the binary config still have
	   the same mtime and ctime. If not, fail the config reading.
	   Changes settings_read() return value to return 1 on success, or 0
	   if timestamps were obsolete. */
	SETTINGS_READ_CHECK_CACHE_TIMESTAMPS = BIT(1),
};

enum settings_get_flags {
	/* Don't call check_func()s */
	SETTINGS_GET_FLAG_NO_CHECK = BIT(0),
	/* Don't expand %variables in settings */
	SETTINGS_GET_FLAG_NO_EXPAND = BIT(1),
	/* Mark %settings as expanded without actually doing it. This is needed
	   while doing checks for settings before expansion is possible. */
	SETTINGS_GET_FLAG_FAKE_EXPAND = BIT(2),

	/* For unit tests: Don't validate that settings struct keys match
	   th binary config file. */
	SETTINGS_GET_NO_KEY_VALIDATION = BIT(3),
	/* Sort filter arrays with defined ordering */
	SETTINGS_GET_FLAG_SORT_FILTER_ARRAYS = BIT(4),
};

struct settings_get_params {
	/* If non-NULL, all %variables are escaped with this function. */
	var_expand_escape_func_t *escape_func;
	void *escape_context;

	enum settings_get_flags flags;
};

/* Setting name prefix that is used as include group. */
#define SETTINGS_INCLUDE_GROUP_PREFIX '@'
#define SETTINGS_INCLUDE_GROUP_PREFIX_S "@"

/* Set struct settings_instance to events so settings_get() can
   use it to get instance-specific settings. */
#define SETTINGS_EVENT_INSTANCE "settings_instance"

/* Used by settings_get() to find struct settings_root via the event.
   This is set automatically by lib-master for all created root events.

   If a new root is created in the event hierarchy (or an instance with a new
   root is used), only the settings under the new root are used. This allows
   specifying the exact wanted settings in the code, and they can't be changed
   with config file or command line options. */
#define SETTINGS_EVENT_ROOT "settings_root"

/* Used by settings_get() to access the named filter. This is copied to the
   temporary lookup event to avoid having to use "filter_name" visible in
   the main event's fields. All the filter names in the event's parents are
   also included in the settings lookup. The filters aren't required to exist
   in the configuration. Usage:

   event_set_ptr(event, SETTINGS_EVENT_FILTER_NAME, "auth_policy"); */
#define SETTINGS_EVENT_FILTER_NAME "settings_filter_name"

/* Set struct var_expand_params to be used for settings expansion. The struct is
   expected to be accessible until the event is freed or the params is removed
   from the event. Usage:

   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, var_expand_params);

   You can set any combination of SETTINGS_EVENT_VAR_EXPAND_PARAMS
   and SETTINGS_EVENT_VAR_EXPAND_CALLBACK to the same event or parent events.
   They are all merged while expanding the variables. */
#define SETTINGS_EVENT_VAR_EXPAND_PARAMS \
	"settings_var_expand_params"

/* Set a settings_var_expand_t callback that returns var_expand_params for
   settings expansion. This can be used instead of
   SETTINGS_EVENT_VAR_EXPAND_PARAMS to dynamically generate the tables
   on-demand. Usage:

   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK, callback);
   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK_CONTEXT, context);
*/
#define SETTINGS_EVENT_VAR_EXPAND_CALLBACK \
	"settings_var_expand_callback"
#define SETTINGS_EVENT_VAR_EXPAND_CALLBACK_CONTEXT \
	"settings_var_expand_callback_context"
/* Callback function used with SETTINGS_EVENT_VAR_EXPAND_CALLBACK. */
typedef void
settings_var_expand_t(void *context, struct var_expand_params *params_r);

/* Get the wanted settings and check that the settings are valid.
   The settings struct must have pool_t (info->pool_offset1), which the caller
   must unreference when done with the settings. settings_free()
   macro can be used to do the freeing in a nice way.

   Settings have their %variables expanded, unless
   SETTINGS_GET_FLAG_NO_EXPAND is used. The event and its
   parents are scanned for SETTINGS_EVENT_VAR_EXPAND_* pointers. The first
   callback or tables that are found in the event hierarchy are used for the
   expansion. See SETTINGS_EVENT_VAR_EXPAND_* macros for more details. */
int settings_get(struct event *event,
		 const struct setting_parser_info *info,
		 enum settings_get_flags flags,
		 const char *source_filename,
		 unsigned int source_linenum,
		 const void **set_r, const char **error_r);
#ifdef HAVE_TYPE_CHECKS
#  define settings_get(event, info, flags, set_r, error_r) \
	settings_get(event, info, flags, \
		__FILE__, __LINE__, (void *)set_r, 1 ? (error_r) : \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof((*set_r)->pool), pool_t)))
#else
#  define settings_get(event, info, flags, set_r, error_r) \
	settings_get(event, info, flags, \
		__FILE__, __LINE__, (void *)set_r, error_r)
#endif

/* Like settings_get(), but support additional parameters. */
int settings_get_params(struct event *event,
			const struct setting_parser_info *info,
			const struct settings_get_params *params,
			const char *source_filename,
			unsigned int source_linenum,
			const void **set_r, const char **error_r);
#ifdef HAVE_TYPE_CHECKS
#  define settings_get_params(event, info, params, set_r, error_r) \
	settings_get_params(event, info, params, \
		__FILE__, __LINE__, (void *)set_r, 1 ? (error_r) : \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof((*set_r)->pool), pool_t)))
#else
#  define settings_get_params(event, info, params, set_r, error_r) \
	settings_get_params(event, info, params, \
		__FILE__, __LINE__, (void *)set_r, error_r)
#endif

/* Same as settings_get(), but looks up settings for a specific named list
   filter. Use e.g. { filter_key="namespace", filter_value="inbox" }.
   Returns 0 on success, -1 on error.

   Settings for the requested "info" must exist inside the specified filter,
   or this lookup fails. This means that you can safely call this to lookup
   e.g. mail_namespace_setting_parser_info for a given namespace, because it's
   required to exist. Using it to lookup any other infos for a namespace will
   fail if settings in it haven't been explicitly used within the namespace
   filter. */
int settings_get_filter(struct event *event,
			const char *filter_key, const char *filter_value,
			const struct setting_parser_info *info,
			enum settings_get_flags flags,
			const char *source_filename,
			unsigned int source_linenum,
			const void **set_r, const char **error_r);
#ifdef HAVE_TYPE_CHECKS
#  define settings_get_filter(event, filter_key, filter_value, info, flags, \
		set_r, error_r) \
	settings_get_filter(event, filter_key, filter_value, info, flags, \
		__FILE__, __LINE__, (void *)set_r, 1 ? (error_r) : \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof((*set_r)->pool), pool_t)))
#else
#  define settings_get_filter(event, filter_key, filter_value, info, flags, \
		set_r, error_r) \
	settings_get_filter(event, filter_key, filter_value, info, flags, \
		__FILE__, __LINE__, (void *)set_r, error_r)
#endif

/* Same as settings_get_filter(), but doesn't fail if the filter doesn't exist.
   Returns 1 if filter exists, 0 if not (set_r is not set), -1 if error. */
int settings_try_get_filter(struct event *event,
			    const char *filter_key, const char *filter_value,
			    const struct setting_parser_info *info,
			    enum settings_get_flags flags,
			    const char *source_filename,
			    unsigned int source_linenum,
			    const void **set_r, const char **error_r);
#ifdef HAVE_TYPE_CHECKS
#  define settings_try_get_filter(event, filter_key, filter_value, info, \
		flags, set_r, error_r) \
	settings_try_get_filter(event, filter_key, filter_value, info, flags, \
		__FILE__, __LINE__, (void *)set_r, 1 ? (error_r) : \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof((*set_r)->pool), pool_t)))
#else
#  define settings_try_get_filter(event, filter_key, filter_value, info, flags, \
		set_r, error_r) \
	settings_try_get_filter(event, filter_key, filter_value, info, flags, \
		__FILE__, __LINE__, (void *)set_r, error_r)
#endif

#ifdef HAVE_TYPE_CHECKS
#  define settings_get_filter(event, filter_key, filter_value, info, \
		flags, set_r, error_r) \
	settings_get_filter(event, filter_key, filter_value, info, flags, \
		__FILE__, __LINE__, (void *)set_r, 1 ? (error_r) : \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof((*set_r)->pool), pool_t)))
#else
#  define settings_get_filter(event, filter_key, filter_value, info, flags, \
		set_r, error_r) \
	settings_get_filter(event, filter_key, filter_value, info, flags, \
		__FILE__, __LINE__, (void *)set_r, error_r)
#endif

/* Like settings_get(), but i_fatal() if there are any errors
   in settings. */
const void *
settings_get_or_fatal(struct event *event,
		      const struct setting_parser_info *info,
		      const char *source_filename,
		      unsigned int source_linenum);
#define settings_get_or_fatal(event, info) \
	settings_get_or_fatal(event, info, __FILE__, __LINE__)
#define settings_free(set) \
	STMT_START { \
		if ((set) != NULL) { \
			pool_t pool_copy = (set)->pool; \
			pool_unref(&pool_copy); \
			(set) = NULL; \
		} \
	} STMT_END

/* Override a setting. */
void settings_override(struct settings_instance *instance,
		       const char *key, const char *value,
		       enum settings_override_type type);
void settings_root_override(struct settings_root *root,
			    const char *key, const char *value,
			    enum settings_override_type type);

/* Remove a setting root override by key and type. */
bool ATTR_NOWARN_UNUSED_RESULT
settings_root_override_remove(struct settings_root *root, const char *key,
			      enum settings_override_type type);

/* Add SETTINGS_EVENT_FILTER_NAME[n]=name as ptr to the event. The name is not
   escaped. */
void settings_event_add_filter_name(struct event *event, const char *name);
/* Add SETTINGS_EVENT_FILTER_NAME[n]=key/value as ptr to the event. The value
   is escaped using settings_section_escape(). */
void settings_event_add_list_filter_name(struct event *event,
					 const char *key, const char *value);

/* Return a new instance for settings. */
struct settings_instance *
settings_instance_new(struct settings_root *root);
/* Return a new instance based on an existing instance. */
struct settings_instance *
settings_instance_dup(const struct settings_instance *src);
/* Free a settings instance. */
void settings_instance_free(struct settings_instance **instance);

/* Read settings. If service_name or protocol_name is non-NULL, all
   non-matching service/protocol filters are dropped immediately and cannot
   be looked up afterwards. */
int settings_read(struct settings_root *root, int fd, const char *path,
		  const char *service_name,
		  const char *protocol_name,
		  enum settings_read_flags flags,
		  const char *const **specific_protocols_r,
		  const char **error_r);
bool settings_has_mmap(struct settings_root *root);

struct settings_root *settings_root_init(void);
void settings_root_deinit(struct settings_root **root);

/* Explicitly register settings info. This is needed if default_settings
   are specified to get the defaults to work when configuration isn't read
   (-O parameter or unit tests). */
void settings_info_register(const struct setting_parser_info *info);

/* Return SETTINGS_EVENT_ROOT from the event or its parents. */
struct settings_root *settings_root_find(const struct event *event);
/* Return SETTINGS_EVENT_INSTANCE from the event or its parents. */
struct settings_instance *settings_instance_find(const struct event *event);

struct settings_simple {
	struct settings_root *root;
	struct settings_instance *instance;
	struct event *event;
};

void settings_simple_init(struct settings_simple *set_r,
			  const char *const settings[]);
void settings_simple_deinit(struct settings_simple *set);
void settings_simple_update(struct settings_simple *set,
			    const char *const settings[]);

#endif
