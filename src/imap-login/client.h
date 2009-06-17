#ifndef CLIENT_H
#define CLIENT_H

#include "network.h"
#include "client-common.h"

/* Disconnect client after idling this many milliseconds */
#define CLIENT_LOGIN_IDLE_TIMEOUT_MSECS (3*60*1000)

struct imap_client {
	struct client common;

	time_t created;
	int refcount;

	struct io *io;
	struct ostream *output;
	struct imap_parser *parser;
	struct timeout *to_idle_disconnect, *to_auth_waiting;
	struct timeout *to_authfail_delay;

	struct login_proxy *proxy;
	char *proxy_user, *proxy_master_user, *proxy_password;
	char *proxy_backend_capability;

	unsigned int bad_counter;

	const char *cmd_tag, *cmd_name;

	unsigned int starttls:1;
	unsigned int login_success:1;
	unsigned int cmd_finished:1;
	unsigned int proxy_sasl_ir:1;
	unsigned int proxy_seen_banner:1;
	unsigned int skip_line:1;
	unsigned int input_blocked:1;
	unsigned int destroyed:1;
	unsigned int greeting_sent:1;
	unsigned int id_logged:1;
	unsigned int auth_initializing:1;
	unsigned int client_ignores_capability_resp_code:1;
};

void client_destroy(struct imap_client *client, const char *reason);
void client_destroy_success(struct imap_client *client, const char *reason);
void client_destroy_internal_failure(struct imap_client *client);

void client_send_line(struct imap_client *client, const char *line);
void client_send_tagline(struct imap_client *client, const char *line);

bool client_read(struct imap_client *client);
bool client_skip_line(struct imap_client *client);
void client_input(struct imap_client *client);

void client_ref(struct imap_client *client);
bool client_unref(struct imap_client *client);

void client_set_auth_waiting(struct imap_client *client);
void client_auth_failed(struct imap_client *client, bool nodelay);

#endif
