#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "../auth/auth-interface.h"

typedef struct _Client Client;
typedef struct _AuthRequest AuthRequest;

extern int disable_plaintext_auth, process_per_connection, verbose_proctitle;
extern unsigned int max_logging_users;
extern unsigned int login_process_uid;

void main_ref(void);
void main_unref(void);

void main_close_listen(void);

#endif
