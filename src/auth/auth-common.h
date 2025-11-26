#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include "lib.h"
#include "auth.h"
#include "connection.h"

extern bool worker, worker_restart_request;
extern time_t process_start_time;
extern struct auth_penalty *auth_penalty;
extern struct event_category event_category_auth;
extern struct event *auth_event;

void auth_refresh_proctitle(void);
void auth_worker_refresh_proctitle(const char *state);
void auth_module_load(const char *name);

static inline const char *auth_driver_filter(const char *prefix, const char *driver)
{
	return t_strconcat(prefix, "_", t_str_replace(driver, '-', '_'), NULL);
}

#endif
