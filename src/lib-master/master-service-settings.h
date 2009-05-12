#ifndef MASTER_SERVICE_SETTINGS_H
#define MASTER_SERVICE_SETTINGS_H

#include "network.h"

struct setting_parser_info;
struct dynamic_settings_parser;
struct master_service;

struct master_service_settings {
	const char *log_path;
	const char *info_log_path;
	const char *log_timestamp;
	const char *syslog_facility;
	bool version_ignore;
};

struct master_service_settings_input {
	const struct setting_parser_info **roots;
	const struct dynamic_settings_parser *dyn_parsers;
	bool preserve_home;

	const char *module;
	const char *service;
	const char *username;
	struct ip_addr local_ip, remote_ip;
};

extern struct setting_parser_info master_service_setting_parser_info;

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 const char **error_r);
int master_service_settings_read_simple(struct master_service *service,
					const struct setting_parser_info **roots,
					const char **error_r);
const struct master_service_settings *
master_service_settings_get(struct master_service *service);
void **master_service_settings_get_others(struct master_service *service);

int master_service_set(struct master_service *service, const char *line);

#endif
