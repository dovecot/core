#ifndef IMAPC_CLIENT_PRIVATE_H
#define IMAPC_CLIENT_PRIVATE_H

#include "imapc-client.h"

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

	ARRAY(struct imapc_client_connection *) conns;

	struct ioloop *ioloop;
};

struct imapc_client_mailbox {
	struct imapc_client *client;
	struct imapc_connection *conn;
	struct imapc_msgmap *msgmap;

	void (*reopen_callback)(void *context);
	void *reopen_context;

	void *untagged_box_context;
	unsigned int pending_box_command_count;

	bool reconnect_ok;
	bool reconnecting;
	bool closing;
};

void imapc_client_ref(struct imapc_client *client);
void imapc_client_unref(struct imapc_client **client);

void imapc_command_set_mailbox(struct imapc_command *cmd,
			       struct imapc_client_mailbox *box);

#endif
