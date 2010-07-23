#ifndef DOVEADM_UTIL_H
#define DOVEADM_UTIL_H

#define DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR 1

extern bool doveadm_verbose, doveadm_debug, doveadm_server;

const char *unixdate2str(time_t timestamp);
const char *doveadm_plugin_getenv(const char *name);
int doveadm_connect(const char *path);

void doveadm_load_modules(void);
void doveadm_unload_modules(void);
bool doveadm_has_unloaded_plugin(const char *name);

#endif
