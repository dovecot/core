#ifndef AUTH_REQUEST_STATS_H
#define AUTH_REQUEST_STATS_H

#include "auth-stats.h"

struct auth_request;

struct auth_stats *auth_request_stats_get(struct auth_request *request);
void auth_request_stats_add_tempfail(struct auth_request *request);
void auth_request_stats_send(struct auth_request *request);

void auth_request_stats_init(void);
void auth_request_stats_deinit(void);

#endif
