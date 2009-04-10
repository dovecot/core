#ifndef MASTER_SERVICE_PRIVATE_H
#define MASTER_SERVICE_PRIVATE_H

#include "master-service.h"

struct master_service {
	struct ioloop *ioloop;

	char *name;
        enum master_service_flags flags;

	int argc;
	char **argv;

	const char *version_string;
	const char *config_path;
	int syslog_facility;

	pool_t set_pool;
	const struct master_service_settings *set;
	struct setting_parser_context *set_parser;

	unsigned int keep_environment:1;
	unsigned int log_directly:1;
};

#endif
