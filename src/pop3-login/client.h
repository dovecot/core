#ifndef CLIENT_H
#define CLIENT_H

#include "network.h"
#include "client-common.h"
#include "auth-client.h"

/* Disconnect client after idling this many milliseconds */
#define CLIENT_LOGIN_IDLE_TIMEOUT_MSECS (3*60*1000)

enum pop3_proxy_state {
	POP3_PROXY_BANNER = 0,
	POP3_PROXY_STARTTLS,
	POP3_PROXY_LOGIN1,
	POP3_PROXY_LOGIN2
};

struct pop3_client {
	struct client common;

	time_t created;
	int refcount;

	struct io *io;
	struct ostream *output;
	struct timeout *to_idle_disconnect, *to_authfail_delay;

	struct login_proxy *proxy;
	char *proxy_user, *proxy_master_user, *proxy_password;
	enum pop3_proxy_state proxy_state;

	unsigned int bad_counter;

	char *last_user;

	char *apop_challenge;
	struct auth_connect_id auth_id;

	unsigned int login_success:1;
	unsigned int auth_connected:1;
	unsigned int auth_initializing:1;
	unsigned int destroyed:1;
};

void client_destroy(struct pop3_client *client, const char *reason);
void client_destroy_success(struct pop3_client *client, const char *reason);
void client_destroy_internal_failure(struct pop3_client *client);

void client_send_line(struct pop3_client *client, const char *line);

bool client_read(struct pop3_client *client);
void client_input(struct pop3_client *client);

void client_ref(struct pop3_client *client);
bool client_unref(struct pop3_client *client);

void client_auth_failed(struct pop3_client *client, bool nodelay);

#endif
