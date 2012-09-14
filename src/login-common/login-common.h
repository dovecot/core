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

#define LOGIN_DEFAULT_SOCKET "login"
#define LOGIN_TOKEN_DEFAULT_SOCKET "tokenlogin"

struct login_binary {
	/* e.g. imap, pop3 */
	const char *protocol;
	/* e.g. imap-login, pop3-login */
	const char *process_name;

	/* e.g. 143, 110 */
	unsigned int default_port;
	/* e.g. 993, 995. if there is no ssl port, use 0. */
	unsigned int default_ssl_port;

	/* if value is NULL, LOGIN_DEFAULT_SOCKET is used as the default */
	const char *default_login_socket;

	const struct client_vfuncs *client_vfuncs;
	void (*preinit)(void);
	void (*init)(void);
	void (*deinit)(void);

	bool sasl_support_final_reply;
};

extern const struct login_binary *login_binary;
extern struct auth_client *auth_client;
extern struct master_auth *master_auth;
extern bool closing_down;
extern struct anvil_client *anvil;
extern const char *login_rawlog_dir;
extern unsigned int initial_service_count;

extern const struct login_settings *global_login_settings;
extern const struct master_service_ssl_settings *global_ssl_settings;
extern void **global_other_settings;

void login_refresh_proctitle(void);
void login_client_destroyed(void);

int login_binary_run(const struct login_binary *binary,
		     int argc, char *argv[]);

#endif
