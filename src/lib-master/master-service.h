#ifndef MASTER_SERVICE_H
#define MASTER_SERVICE_H

#include "network.h"

enum master_service_flags {
	/* stdin/stdout already contains a client which we want to serve */
	MASTER_SERVICE_FLAG_STD_CLIENT		= 0x01,
	/* this process is currently running standalone without a master */
	MASTER_SERVICE_FLAG_STANDALONE		= 0x02,
	/* Log to stderr instead of the configured log file */
	MASTER_SERVICE_FLAG_LOG_TO_STDERR	= 0x04
};

struct master_service;

const char *master_service_getopt_string(void);

/* Start service initialization. */
struct master_service *
master_service_init(const char *name, enum master_service_flags flags,
		    int argc, char *argv[]);
/* Parser command line option. Returns TRUE if processed. */
bool master_service_parse_option(struct master_service *service,
				 int opt, const char *arg);

/* Clean environment from everything except TZ, USER and optionally HOME. */
void master_service_env_clean(bool preserve_home);

/* Initialize logging. */
void master_service_init_log(struct master_service *service,
			     const char *prefix);

/* Returns configuration file path. */
const char *master_service_get_config_path(struct master_service *service);
/* Returns PACKAGE_VERSION or NULL if version_ignore=yes. This function is
   useful mostly as parameter to module_dir_load(). */
const char *master_service_get_version_string(struct master_service *service);

/* Start the service. Blocks until finished */
void master_service_run(struct master_service *service);
/* Stop a running service. */
void master_service_stop(struct master_service *service);

/* Deinitialize the service. */
void master_service_deinit(struct master_service **service);

#endif
