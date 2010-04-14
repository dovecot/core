#ifndef LOGIN_COMMON_H
#define LOGIN_COMMON_H

#include "lib.h"
#include "login-settings.h"

/* Used only for string sanitization */
#define MAX_MECH_NAME 64

#define AUTH_FAILED_MSG "Authentication failed."
#define AUTH_TEMP_FAILED_MSG "Temporary authentication failure."
#define AUTH_PLAINTEXT_DISABLED_MSG \
	"Plaintext authentication disallowed on non-secure (SSL/TLS) connections."

extern const char *login_protocol, *login_process_name;
extern unsigned int login_default_port, login_default_ssl_port;

extern struct auth_client *auth_client;
extern struct master_auth *master_auth;
extern bool closing_down;
extern struct anvil_client *anvil;

extern const struct login_settings *global_login_settings;
extern void **global_other_settings;

void login_refresh_proctitle(void);
void login_client_destroyed(void);

void login_process_preinit(void);

#endif
