#ifndef IMAPC_CONNECTION_H
#define IMAPC_CONNECTION_H

#include "imapc-client.h"

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

/* Called when connection state changes */
typedef void
imapc_connection_state_change(struct imapc_connection *conn,
			      struct imapc_client *client,
			      enum imapc_connection_state prev_state);

struct imapc_connection *
imapc_connection_init(struct imapc_client *client,
		      imapc_connection_state_change *state_callback);
void imapc_connection_deinit(struct imapc_connection **conn);

void imapc_connection_connect(struct imapc_connection *conn);
void imapc_connection_ioloop_changed(struct imapc_connection *conn);

void imapc_connection_cmd(struct imapc_connection *conn, const char *cmdline,
			  imapc_command_callback_t *callback, void *context);
void imapc_connection_cmdf(struct imapc_connection *conn,
			   imapc_command_callback_t *callback, void *context,
			   const char *cmd_fmt, ...) ATTR_FORMAT(4, 5);
void imapc_connection_cmdvf(struct imapc_connection *conn,
			    imapc_command_callback_t *callback, void *context,
			    const char *cmd_fmt, va_list args)
	ATTR_FORMAT(4, 0);
void imapc_connection_select(struct imapc_client_mailbox *box, const char *name,
			     imapc_command_callback_t *callback, void *context);

enum imapc_connection_state
imapc_connection_get_state(struct imapc_connection *conn);
enum imapc_capability
imapc_connection_get_capabilities(struct imapc_connection *conn);

void imapc_connection_idle(struct imapc_connection *conn);

#endif
