#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "../auth/auth-interface.h"

typedef struct _Client Client;
typedef struct _AuthRequest AuthRequest;

extern IOLoop ioloop;
extern int disable_plaintext_auth;
extern unsigned int max_logging_users;

#endif
