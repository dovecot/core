#ifndef MASTER_SERVICE_SETTINGS_H
#define MASTER_SERVICE_SETTINGS_H

#include "network.h"

struct setting_parser_info;
struct dynamic_settings_parser;
struct master_service;

struct master_service_settings {
	const char *log_path;
	const char *info_log_path;
	const char *debug_log_path;
	const char *log_timestamp;
	const char *syslog_facility;
	bool version_ignore;
	bool shutdown_clients;
};

struct master_service_settings_input {
	const struct setting_parser_info **roots;
	const struct dynamic_settings_parser *dyn_parsers;
	struct setting_parser_info *dyn_parsers_parent;
	const char *config_path;
	bool preserve_home;

	const char *module;
	const char *service;
	const char *username;
	struct ip_addr local_ip, remote_ip;
	const char *local_host, *remote_host;
};

extern const struct setting_parser_info master_service_setting_parser_info;

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
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

int master_service_set(struct master_service *service, const char *line);

#endif
