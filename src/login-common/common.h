#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"

#define AUTH_FAILED_MSG "Authentication failed."
#define AUTH_TEMP_FAILED_MSG "Temporary authentication failure."

extern int disable_plaintext_auth, process_per_connection, greeting_capability;
extern int verbose_proctitle, verbose_ssl, verbose_auth;
char *greeting;
extern unsigned int max_logging_users;
extern unsigned int login_process_uid;
extern struct auth_client *auth_client;

void main_ref(void);
void main_unref(void);

void main_close_listen(void);

#endif
