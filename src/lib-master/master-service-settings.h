#ifndef MASTER_SERVICE_SETTINGS_H
#define MASTER_SERVICE_SETTINGS_H

#include "net.h"
#include "settings-parser.h"

struct var_expand_table;
struct var_expand_func_table;
struct master_service;
struct settings_mmap;
struct settings_instance;

enum master_service_set_type {
	/* Setting is from userdb. */
	MASTER_SERVICE_SET_TYPE_USERDB,
	/* Setting is from -o command line parameters. */
	MASTER_SERVICE_SET_TYPE_CLI_PARAM,
	/* Setting is hardcoded to be overridden in the code. */
	MASTER_SERVICE_SET_TYPE_CODE,

	MASTER_SERVICE_SET_TYPE_COUNT,
};

enum master_service_settings_get_flags {
	/* Don't call check_func()s */
	MASTER_SERVICE_SETTINGS_GET_FLAG_NO_CHECK = BIT(0),
	/* Don't expand %variables in settings */
	MASTER_SERVICE_SETTINGS_GET_FLAG_NO_EXPAND = BIT(1),
};

struct master_service_settings {
	pool_t pool;
	const char *base_dir;
	const char *state_dir;
	const char *instance_name;
	const char *log_path;
	const char *info_log_path;
	const char *debug_log_path;
	const char *log_timestamp;
	const char *log_debug;
	const char *log_core_filter;
	const char *process_shutdown_filter;
	const char *syslog_facility;
	const char *import_environment;
	const char *stats_writer_socket_path;
	bool version_ignore;
	bool shutdown_clients;
	bool verbose_proctitle;

	const char *haproxy_trusted_networks;
	unsigned int haproxy_timeout;
};

struct master_service_settings_input {
	const char *config_path;
	/* Read configuration from given fd. This is intended for unit tests. */
	int config_fd;
	bool preserve_environment;
	bool preserve_user;
	bool preserve_home;
	/* When execing via doveconf, the errors in settings' values are
	   delayed until the settings struct is actually accessed. Enabling
	   this causes an immediate failure. (With config UNIX socket lookups
	   this does nothing, since config process always checks the full
	   config anyway). */
	bool check_full_config;
	/* If executing via doveconf, hide warnings about obsolete settings. */
	bool hide_obsolete_warnings;
	bool reload_config;
	bool never_exec;
	bool always_exec;
	bool return_config_fd;
	bool use_sysexits;

	const char *protocol;
};

struct master_service_settings_output {
	/* if service was not given for lookup, this contains names of services
	   that have more specific settings */
	const char *const *specific_services;
	/* Configuration file fd. Returned if input.return_config_fd=TRUE. */
	int config_fd;

	/* Config couldn't be read because we don't have enough permissions.
	   The process probably should be restarted and the settings read
	   before dropping privileges. */
	bool permission_denied:1;
};

/* Set struct settings_instance to events so master_service_settings_get() can
   use it to get instance-specific settings. */
#define MASTER_SERVICE_SETTINGS_INSTANCE \
	"master_service_settings_instance"

/* Set struct var_expand_table to be used for settings expansion. The table is
   expected to be accessible until the event is freed or the table is cleared
   from the event. Usage:

   event_set_ptr(event, MASTER_SERVICE_VAR_EXPAND_TABLE, var_expand_table);
*/
#define MASTER_SERVICE_VAR_EXPAND_TABLE \
	"master_service_var_expand_table"
/* Set struct var_expand_func_table and its function context pointer to be used
   for settings expansion. The table is expected to be accessible until the
   event is freed or the table is cleared from the event. Usage:

   event_set_ptr(event, MASTER_SERVICE_VAR_EXPAND_FUNC_TABLE, func_table);
   event_set_ptr(event, MASTER_SERVICE_VAR_EXPAND_FUNC_CONTEXT, func_context);

   You can set either or both of MASTER_SERVICE_VAR_EXPAND_TABLE and
   MASTER_SERVICE_VAR_EXPAND_FUNC_TABLE for the same event. The parent events
   won't be searched for either of them if either one is set.
*/
#define MASTER_SERVICE_VAR_EXPAND_FUNC_TABLE \
	"master_service_var_expand_func_table"
#define MASTER_SERVICE_VAR_EXPAND_FUNC_CONTEXT \
	"master_service_var_expand_func_context"

/* Set a master_service_settings_var_expand_t callback that returns
   var_expand_[func_]table for settings expansion. This can be used instead of
   MASTER_SERVICE_VAR_EXPAND_[FUNC_]TABLE to dynamically generate the table
   on-demand. If this is found from the event, all other MASTER_SERVICE_VAR_*
   fields are ignored in this and the parent events. Usage:

   event_set_ptr(event, MASTER_SERVICE_VAR_EXPAND_CALLBACK, callback);
   event_set_ptr(event, MASTER_SERVICE_VAR_EXPAND_FUNC_CONTEXT, func_context);
*/
#define MASTER_SERVICE_VAR_EXPAND_CALLBACK \
	"master_service_var_expand_callback"
/* Callback function used with MASTER_SERVICE_VAR_EXPAND_CALLBACK. The function
   can return either or both of tab_r and func_tab_r, using NULL for the field
   that isn't needed. */
typedef void
master_service_settings_var_expand_t(struct event *event,
				     const struct var_expand_table **tab_r,
				     const struct var_expand_func_table **func_tab_r);

extern const struct setting_parser_info master_service_setting_parser_info;

void settings_mmap_ref(struct settings_mmap *mmap);
void settings_mmap_unref(struct settings_mmap **mmap);

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 struct master_service_settings_output *output_r,
				 const char **error_r);
int master_service_settings_read_simple(struct master_service *service,
					const char **error_r);

const struct master_service_settings *
master_service_get_service_settings(struct master_service *service);

/* Get the wanted settings and check that the settings are valid.
   The settings struct must have pool_t (info->pool_offset1), which the caller
   must unreference when done with the settings. master_service_settings_free()
   macro can be used to do the freeing in a nice way.

   Settings have their %variables expanded, unless
   MASTER_SERVICE_SETTINGS_GET_FLAG_NO_EXPAND is used. The event and its
   parents are scanned for MASTER_SERVICE_VAR_EXPAND_* pointers. The first
   callback or tables that are found in the event hierarchy are used for the
   expansion. See MASTER_SERVICE_VAR_EXPAND_* macros for more details. */
int master_service_settings_get(struct event *event,
				const struct setting_parser_info *info,
				enum master_service_settings_get_flags flags,
				const char *source_filename,
				unsigned int source_linenum,
				const void **set_r, const char **error_r);
#ifdef HAVE_TYPE_CHECKS
#  define master_service_settings_get(event, info, flags, set_r, error_r) \
	master_service_settings_get(event, info, flags, \
		__FILE__, __LINE__, (void *)set_r, 1 ? (error_r) : \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof((*set_r)->pool), pool_t)))
#else
#  define master_service_settings_get(event, info, flags, set_r, error_r) \
	master_service_settings_get(event, info, flags, \
		__FILE__, __LINE__, (void *)set_r, error_r)
#endif

/* Like master_service_settings_get(), but i_fatal() if there are any errors
   in settings. */
const void *
master_service_settings_get_or_fatal(struct event *event,
				     const struct setting_parser_info *info,
				     const char *source_filename,
				     unsigned int source_linenum);
#define master_service_settings_get_or_fatal(event, info) \
	master_service_settings_get_or_fatal(event, info, __FILE__, __LINE__)
#define master_service_settings_free(set) \
	STMT_START { \
		if ((set) != NULL) { \
			pool_t pool_copy = set->pool; \
			pool_unref(&pool_copy); \
			(set) = NULL; \
		} \
	} STMT_END

/* Override a setting. */
void master_service_set(struct settings_instance *instance,
			const char *key, const char *value,
			enum master_service_set_type type);

/* Return a new instance for settings. */
struct settings_instance *
settings_instance_new(struct master_service *service);
/* Return a new instance based on an existing instance. */
struct settings_instance *
settings_instance_dup(const struct settings_instance *src);
/* Free a settings instance. */
void settings_instance_free(struct settings_instance **instance);

void master_service_settings_deinit(struct master_service *service);

#endif
