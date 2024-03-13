#ifndef IMAPC_CLIENT_PRIVATE_H
#define IMAPC_CLIENT_PRIVATE_H

#include "imapc-client.h"
#include "imapc-settings.h"

#define IMAPC_CLIENT_IDLE_SEND_DELAY_MSECS 100

enum imapc_client_ssl_mode {
	IMAPC_CLIENT_SSL_MODE_NONE,
	IMAPC_CLIENT_SSL_MODE_IMMEDIATE,
	IMAPC_CLIENT_SSL_MODE_STARTTLS
};

struct imapc_client_connection {
	struct imapc_connection *conn;
	struct imapc_client *client;
	struct imapc_client_mailbox *box;
};

struct imapc_client {
	pool_t pool;
	int refcount;

	struct event *event;
	const struct imapc_settings *set;
	struct imapc_parameters params;
	enum imapc_client_ssl_mode ssl_mode;

	imapc_untagged_callback_t *untagged_callback;
	void *untagged_context;

	imapc_state_change_callback_t *state_change_callback;
	void *state_change_context;

	imapc_command_callback_t *login_callback;
	void *login_context;

	ARRAY(struct imapc_client_connection *) conns;
	bool logging_out;

	struct ioloop *ioloop;
	bool stop_on_state_finish;

	/* Set to imapc_settings attributes with possible override by the
	   imapc_parameters. */
	const char *dns_client_socket_path;
	const char *imapc_rawlog_dir;
	const char *password;
};

struct imapc_client_mailbox {
	struct imapc_client *client;
	struct imapc_connection *conn;
	struct imapc_msgmap *msgmap;
	struct timeout *to_send_idle;

	void (*reopen_callback)(void *context);
	void *reopen_context;

	void *untagged_box_context;

	bool reconnect_ok;
	bool reconnecting;
	bool closing;
};

extern unsigned int imapc_client_cmd_tag_counter;

void imapc_client_ref(struct imapc_client *client);
void imapc_client_unref(struct imapc_client **client);

void imapc_command_set_mailbox(struct imapc_command *cmd,
			       struct imapc_client_mailbox *box);
void imapc_client_try_stop(struct imapc_client *client);

#endif
