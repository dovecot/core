#ifndef DOVEADM_UTIL_H
#define DOVEADM_UTIL_H

#include "net.h"

struct connection_settings;

extern bool doveadm_verbose, doveadm_debug, doveadm_server;

const char *unixdate2str(time_t timestamp);
const char *doveadm_plugin_getenv(const char *name);
int doveadm_connect(const char *path);
int doveadm_tcp_connect(const char *target, in_port_t default_port);
int doveadm_connect_with_default_port(const char *path,
				      in_port_t default_port);

/* Connect to a connection API compatible UNIX socket. */
int doveadm_blocking_connect(const char *path,
			     const struct connection_settings *set,
			     struct istream **input_r,
			     struct ostream **output_r, const char **error_r);

void doveadm_load_modules(void);
void doveadm_unload_modules(void);
bool doveadm_has_unloaded_plugin(const char *name);

/* Similar to strcmp(), except "camel case" == "camel-case" == "camelCase".
   Otherwise the comparison is case-sensitive. */
int i_strccdascmp(const char *a, const char *b) ATTR_PURE;

#endif
