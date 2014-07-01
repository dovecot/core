#ifndef MASTER_SERVICE_SETTINGS_H
#define MASTER_SERVICE_SETTINGS_H

#include "net.h"

struct setting_parser_info;
struct setting_parser_context;
struct master_service;

struct master_service_settings {
	const char *base_dir;
	const char *state_dir;
	const char *instance_name;
	const char *log_path;
	const char *info_log_path;
	const char *debug_log_path;
	const char *log_timestamp;
	const char *log_debug;
	const char *log_core_filter;
	const char *syslog_facility;
	const char *import_environment;
	const char *stats_writer_socket_path;
	uoff_t config_cache_size;
	bool version_ignore;
	bool shutdown_clients;
	bool verbose_proctitle;

	const char *haproxy_trusted_networks;
	unsigned int haproxy_timeout;
};

struct master_service_settings_input {
	const struct setting_parser_info *const *roots;
	const char *config_path;
	bool preserve_environment;
	bool preserve_user;
	bool preserve_home;
	bool never_exec;
	bool use_sysexits;
	bool parse_full_config;

	const char *module;
	const char *service;
	const char *username;
	struct ip_addr local_ip, remote_ip;
	const char *local_name;
};

struct master_service_settings_output {
	/* if service was not given for lookup, this contains names of services
	   that have more specific settings */
	const char *const *specific_services;

	/* some settings for this service (or if service was not given,
	   all services) contain local/remote ip/host specific settings
	   (but this lookup didn't necessarily return any of them). */
	bool service_uses_local:1;
	bool service_uses_remote:1;
	/* returned settings contain settings specific to given
	   local/remote ip/host */
	bool used_local:1;
	bool used_remote:1;
	/* Config couldn't be read because we don't have enough permissions.
	   The process probably should be restarted and the settings read
	   before dropping privileges. */
	bool permission_denied:1;
};

extern const struct setting_parser_info master_service_setting_parser_info;

/* Try to open the config socket if it's going to be needed later by
   master_service_settings_read*() */
void master_service_config_socket_try_open(struct master_service *service);
int master_service_settings_get_filters(struct master_service *service,
					const char *const **filters,
					const char **error_r);
int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 struct master_service_settings_output *output_r,
				 const char **error_r);
int master_service_settings_read_simple(struct master_service *service,
					const struct setting_parser_info **roots,
					const char **error_r) ATTR_NULL(2);
/* destroy settings parser and clear service's set_pool, so that
   master_service_settings_read*() can be called without freeing memory used
   by existing settings structures. */
pool_t master_service_settings_detach(struct master_service *service);

const struct master_service_settings *
master_service_settings_get(struct master_service *service);
void **master_service_settings_get_others(struct master_service *service);
void **master_service_settings_parser_get_others(struct master_service *service,
						 const struct setting_parser_context *set_parser);
struct setting_parser_context *
master_service_get_settings_parser(struct master_service *service);

int master_service_set(struct master_service *service, const char *line);

/* Returns TRUE if -o key=value parameter was used. Setting keys in overrides
   and parameter are unaliased before comparing. */
bool master_service_set_has_config_override(struct master_service *service,
					    const char *key);

/* Parse log filter setting into an event filter. */
int master_service_log_filter_parse(struct event_filter *filter, const char *str,
				    const char **error_r);

#endif
