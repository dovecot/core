#ifndef IMAPC_CLIENT_PRIVATE_H
#define IMAPC_CLIENT_PRIVATE_H

#include "imapc-client.h"

#define IMAPC_CLIENT_IDLE_SEND_DELAY_MSECS 100

struct imapc_client_connection {
	struct imapc_connection *conn;
	struct imapc_client_mailbox *box;
};

struct imapc_client {
	pool_t pool;
	int refcount;

	struct imapc_client_settings set;
	struct ssl_iostream_context *ssl_ctx;

	imapc_untagged_callback_t *untagged_callback;
	void *untagged_context;

	imapc_state_change_callback_t *state_change_callback;
	void *state_change_context;

	ARRAY(struct imapc_client_connection *) conns;
	bool logging_out;

	struct ioloop *ioloop;
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

void imapc_client_ref(struct imapc_client *client);
void imapc_client_unref(struct imapc_client **client);

void imapc_command_set_mailbox(struct imapc_command *cmd,
			       struct imapc_client_mailbox *box);
void imapc_client_try_stop(struct imapc_client *client);

#endif
