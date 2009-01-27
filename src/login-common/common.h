#ifndef COMMON_H
#define COMMON_H

#include "lib.h"
#include "login-settings.h"

/* Used only for string sanitization */
#define MAX_MECH_NAME 64

#define AUTH_FAILED_MSG "Authentication failed."
#define AUTH_TEMP_FAILED_MSG "Temporary authentication failure."
#define AUTH_PLAINTEXT_DISABLED_MSG \
	"Plaintext authentication disallowed on non-secure (SSL/TLS) connections."

extern const char *login_protocol;

extern struct auth_client *auth_client;
extern bool closing_down;
extern unsigned int login_process_uid;

extern struct login_settings *login_settings;

void main_ref(void);
void main_unref(void);

void main_listen_start(void);
void main_listen_stop(void);

void connection_queue_add(unsigned int connection_count);

#endif
