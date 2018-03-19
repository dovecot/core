#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include "lib.h"
#include "auth.h"

extern bool worker, worker_restart_request;
extern time_t process_start_time;
extern struct auth_penalty *auth_penalty;
extern struct event_category event_category_auth;
extern struct event *auth_event;

void auth_refresh_proctitle(void);
void auth_worker_refresh_proctitle(const char *state);
void auth_module_load(const char *names);

#endif
