#ifndef SETTINGS_H
#define SETTINGS_H

struct var_expand_table;
struct var_expand_func_table;

struct setting_parser_info;
struct settings_root;
struct settings_mmap;
struct settings_instance;

enum settings_override_type {
	/* Setting is from userdb. */
	SETTINGS_OVERRIDE_TYPE_USERDB,
	/* Setting is from -o command line parameters. */
	SETTINGS_OVERRIDE_TYPE_CLI_PARAM,
	/* Setting is hardcoded to be overridden in the code. */
	SETTINGS_OVERRIDE_TYPE_CODE,

	SETTINGS_OVERRIDE_TYPE_COUNT,
};

enum settings_read_flags {
	/* Don't drop filters that contain a mismatching protocol */
	SETTINGS_READ_NO_PROTOCOL_FILTER = BIT(0),
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
};

/* Set struct settings_instance to events so settings_get() can
   use it to get instance-specific settings. */
#define SETTINGS_EVENT_INSTANCE "settings_instance"

/* Used by settings_get() to find struct settings_root via the event.
   This is set automatically by lib-master for all created root events. */
#define SETTINGS_EVENT_ROOT "settings_root"

/* Used by settings_get() to access the named filter. This is copied to the
   temporary lookup event to avoid having to use "filter_name" visible in
   the main event's fields. Usage:

   event_set_ptr(event, SETTINGS_EVENT_FILTER_NAME, "auth_policy"); */
#define SETTINGS_EVENT_FILTER_NAME "settings_filter_name"

/* The "mailbox" event field contains the full mailbox with namespace prefix.
   However, for settings we need to use the mailbox name without the namespace
   prefix. Internally convert the "mailbox" named filters to "mailbox_subname",
   so the matching works for the event. */
#define SETTINGS_EVENT_MAILBOX_NAME_WITH_PREFIX "mailbox"
#define SETTINGS_EVENT_MAILBOX_NAME_WITHOUT_PREFIX "mailbox_subname"

/* Set struct var_expand_table to be used for settings expansion. The table is
   expected to be accessible until the event is freed or the table is cleared
   from the event. Usage:

   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_TABLE, var_expand_table);
*/
#define SETTINGS_EVENT_VAR_EXPAND_TABLE \
	"settings_var_expand_table"
/* Set struct var_expand_func_table and its function context pointer to be used
   for settings expansion. The table is expected to be accessible until the
   event is freed or the table is cleared from the event. Usage:

   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_FUNC_TABLE, func_table);
   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_FUNC_CONTEXT, func_context);

   You can set either or both of SETTINGS_EVENT_VAR_EXPAND_TABLE and
   SETTINGS_EVENT_VAR_EXPAND_FUNC_TABLE for the same event. The parent events
   won't be searched for either of them if either one is set.
*/
#define SETTINGS_EVENT_VAR_EXPAND_FUNC_TABLE \
	"settings_var_expand_func_table"
#define SETTINGS_EVENT_VAR_EXPAND_FUNC_CONTEXT \
	"settings_var_expand_func_context"

/* Set a settings_var_expand_t callback that returns
   var_expand_[func_]table for settings expansion. This can be used instead of
   SETTINGS_EVENT_VAR_EXPAND_[FUNC_]TABLE to dynamically generate the table
   on-demand. If this is found from the event, all other SETTINGS_EVENT_VAR_*
   fields are ignored in this and the parent events. Usage:

   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK, callback);
   event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_FUNC_CONTEXT, func_context);
*/
#define SETTINGS_EVENT_VAR_EXPAND_CALLBACK \
	"settings_var_expand_callback"
/* Callback function used with SETTINGS_EVENT_VAR_EXPAND_CALLBACK. The function
   can return either or both of tab_r and func_tab_r, using NULL for the field
   that isn't needed. */
typedef void
settings_var_expand_t(struct event *event,
		      const struct var_expand_table **tab_r,
		      const struct var_expand_func_table **func_tab_r);

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

/* Same as settings_get(), but looks up settings for a specific named array
   filter. Use e.g. { filter_key="namespace", filter_value="inbox" }.
   Returns 0 on success, -1 on error. */
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
   Returns 1 if filter exists, 0 if not, -1 if error. */
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
			pool_t pool_copy = set->pool; \
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
		  const char *const **specific_services_r,
		  const char **error_r);
bool settings_has_mmap(struct settings_root *root);

struct settings_root *settings_root_init(void);
void settings_root_deinit(struct settings_root **root);

#endif
