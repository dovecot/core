#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "auth.h"

#define MASTER_SOCKET_FD 0
#define LOGIN_LISTEN_FD 3

extern struct ioloop *ioloop;
extern int verbose, verbose_debug;
extern int standalone;

#endif
