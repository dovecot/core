#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include "lib.h"
#include "auth.h"

extern bool worker, shutdown_request;
extern time_t process_start_time;
extern struct auth_penalty *auth_penalty;

void auth_refresh_proctitle(void);

#endif
