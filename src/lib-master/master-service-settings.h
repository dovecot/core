#ifndef MASTER_SERVICE_SETTINGS_H
#define MASTER_SERVICE_SETTINGS_H

#include "network.h"

struct setting_parser_info;
struct master_service;

struct master_service_settings {
	const char *log_path;
	const char *info_log_path;
	const char *debug_log_path;
	const char *log_timestamp;
	const char *syslog_facility;
	uoff_t config_cache_size;
	bool version_ignore;
	bool shutdown_clients;
	bool verbose_proctitle;
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
	unsigned int service_uses_local:1;
	unsigned int service_uses_remote:1;
	/* returned settings contain settings specific to given
	   local/remote ip/host */
	unsigned int used_local:1;
	unsigned int used_remote:1;
};

extern const struct setting_parser_info master_service_setting_parser_info;

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 struct master_service_settings_output *output_r,
				 const char **error_r);
int master_service_settings_read_simple(struct master_service *service,
					const struct setting_parser_info **roots,
					const char **error_r);
/* destroy settings parser and clear service's set_pool, so that
   master_service_settings_read*() can be called without freeing memory used
   by existing settings structures. */
pool_t master_service_settings_detach(struct master_service *service);

const struct master_service_settings *
master_service_settings_get(struct master_service *service);
void **master_service_settings_get_others(struct master_service *service);
struct setting_parser_context *
master_service_get_settings_parser(struct master_service *service);

int master_service_set(struct master_service *service, const char *line);

/* Returns TRUE if -o key=value parameter was used. Setting keys in overrides
   and parameter are unaliased before comparing. */
bool master_service_set_has_config_override(struct master_service *service,
					    const char *key);

#endif
