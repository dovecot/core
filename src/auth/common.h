#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "auth.h"

#define MASTER_SOCKET_FD 0
#define CLIENT_LISTEN_FD 3
#define BALANCER_LISTEN_FD 4

extern struct ioloop *ioloop;
extern int standalone;
extern time_t process_start_time;

#endif
