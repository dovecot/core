#ifndef COMMON_H
#define COMMON_H

#include "lib.h"

/* Used only for string sanitization */
#define MAX_MECH_NAME 64

#define AUTH_FAILED_MSG "Authentication failed."
#define AUTH_TEMP_FAILED_MSG "Temporary authentication failure."
#define AUTH_PLAINTEXT_DISABLED_MSG \
	"Plaintext authentication disallowed on non-secure (SSL/TLS) connections."

extern const char *login_protocol;

extern bool disable_plaintext_auth, process_per_connection;
extern bool verbose_proctitle, verbose_ssl, verbose_auth, auth_debug;
extern bool ssl_required, ssl_require_client_cert;
extern const char *greeting, *log_format;
extern const char *const *log_format_elements;
extern const char *capability_string;
extern const char *trusted_networks;
extern unsigned int max_connections;
extern unsigned int login_process_uid;
extern struct auth_client *auth_client;
extern bool closing_down;

void main_ref(void);
void main_unref(void);

void main_listen_start(void);
void main_listen_stop(void);

void connection_queue_add(unsigned int connection_count);

#endif
