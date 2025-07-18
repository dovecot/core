#ifndef IMAPC_CONNECTION_H
#define IMAPC_CONNECTION_H

#include "imapc-client.h"

/* [THROTTLED] handling behavior */
#define IMAPC_THROTTLE_DEFAULT_INIT_MSECS 50
#define IMAPC_THROTTLE_DEFAULT_MAX_MSECS (16*1000)
#define IMAPC_THROTTLE_DEFAULT_SHRINK_MIN_MSECS 500

struct imapc_client;
struct imapc_connection;

enum imapc_connection_state {
	/* No connection */
	IMAPC_CONNECTION_STATE_DISCONNECTED = 0,
	/* Trying to connect */
	IMAPC_CONNECTION_STATE_CONNECTING,
	/* Connected, trying to authenticate */
	IMAPC_CONNECTION_STATE_AUTHENTICATING,
	/* Authenticated, ready to accept commands */
	IMAPC_CONNECTION_STATE_DONE
};

struct imapc_connection *
imapc_connection_init(struct imapc_client *client,
		      imapc_command_callback_t *login_callback,
		      void *login_context);
void imapc_connection_deinit(struct imapc_connection **conn);

void imapc_connection_connect(struct imapc_connection *conn);
void imapc_connection_set_no_reconnect(struct imapc_connection *conn);
void imapc_connection_disconnect(struct imapc_connection *conn);
void imapc_connection_disconnect_full(struct imapc_connection *conn,
				      bool reconnecting);
void imapc_connection_try_reconnect(struct imapc_connection *conn,
				    const char *errstr,
				    unsigned int delay_msecs,
				    bool connect_error);
void imapc_connection_abort_commands(struct imapc_connection *conn,
				     struct imapc_client_mailbox *only_box,
				     bool keep_retriable) ATTR_NULL(2);
void imapc_connection_ioloop_changed(struct imapc_connection *conn);
void imapc_connection_input_pending(struct imapc_connection *conn);

struct imapc_command *
imapc_connection_cmd(struct imapc_connection *conn,
		     imapc_command_callback_t *callback, void *context)
	ATTR_NULL(3);

void imapc_connection_unselect(struct imapc_client_mailbox *box,
			       bool via_tagged_reply);

enum imapc_connection_state
imapc_connection_get_state(struct imapc_connection *conn);
enum imapc_capability
imapc_connection_get_capabilities(struct imapc_connection *conn);
bool imapc_cmd_has_imap4rev2(struct imapc_command *cmd);
struct imapc_client_mailbox *
imapc_connection_get_mailbox(struct imapc_connection *conn);

void imapc_connection_idle(struct imapc_connection *conn);
struct event *imapc_connection_get_event(struct imapc_connection *conn);

#endif
