#ifndef SERVER_CONNECTION_H
#define SERVER_CONNECTION_H

enum server_cmd_reply {
	SERVER_CMD_REPLY_INTERNAL_FAILURE,
	SERVER_CMD_REPLY_FAIL,
	SERVER_CMD_REPLY_OK
};

struct doveadm_server;

typedef void server_cmd_callback_t(enum server_cmd_reply reply, void *context);

struct server_connection *
server_connection_create(struct doveadm_server *server);
void server_connection_destroy(struct server_connection **conn);

/* Return the server given to create() */
struct doveadm_server *
server_connection_get_server(struct server_connection *conn);

void server_connection_cmd(struct server_connection *conn, const char *line,
			   server_cmd_callback_t *callback, void *context);
/* Returns TRUE if no command is being processed */
bool server_connection_is_idle(struct server_connection *conn);

#endif
