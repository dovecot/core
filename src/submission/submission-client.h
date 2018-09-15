#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "submission-backend-relay.h"

struct smtp_reply;

struct submission_recipient;
struct submission_backend;
struct client;

struct client_state {
	struct istream *data_input;
	uoff_t data_size;
};

struct client {
	struct client *prev, *next;
	char *session_id;

	const struct setting_parser_info *user_set_info;
	const struct submission_settings *set;

	struct smtp_server_connection *conn;
	enum smtp_server_state last_state;
	struct client_state state;
	ARRAY(struct submission_recipient *) rcpt_to;

	struct mail_storage_service_user *service_user;
	struct mail_user *user;

	/* IMAP URLAUTH context (RFC4467) for BURL (RFC4468) */
	struct imap_urlauth_context *urlauth_ctx;

	struct timeout *to_quit;

	struct smtp_server_stats stats;

	enum smtp_capability backend_capabilities;
	struct submission_backend_relay backend;
	struct submission_backend *backend_default;
	struct submission_backend *backends;
	unsigned int backends_count;

	bool standalone:1;
	bool disconnected:1;
	bool destroyed:1;
	bool anvil_sent:1;
	bool backend_capabilities_configured:1;
};

extern struct client *submission_clients;
extern unsigned int submission_client_count;

struct client *client_create(int fd_in, int fd_out,
			     const char *session_id, struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct submission_settings *set,
			     const char *helo,
			     const unsigned char *pdata,
			     unsigned int pdata_len);
void client_destroy(struct client *client, const char *prefix,
		    const char *reason) ATTR_NULL(2, 3);
void client_disconnect(struct client *client, const char *prefix,
		       const char *reason);

typedef void (*client_input_callback_t)(struct client *context);

void client_apply_backend_capabilities(struct client *client);
void client_default_backend_started(struct client *client,
				    enum smtp_capability caps);

const char *client_state_get_name(struct client *client);

uoff_t client_get_max_mail_size(struct client *client);

int client_input_read(struct client *client);
int client_handle_input(struct client *client);

void clients_destroy_all(void);

#endif
