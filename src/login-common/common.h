#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"

extern int disable_plaintext_auth, process_per_connection, verbose_proctitle;
extern int verbose_ssl;
extern unsigned int max_logging_users;
extern unsigned int login_process_uid;
extern struct auth_client *auth_client;

void main_ref(void);
void main_unref(void);

void main_close_listen(void);

#endif
