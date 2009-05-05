#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include "lib.h"
#include "auth.h"

extern struct master_service *service;
extern bool worker, shutdown_request;
extern time_t process_start_time;

#endif
