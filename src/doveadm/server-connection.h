#ifndef SERVER_CONNECTION_H
#define SERVER_CONNECTION_H

#define SERVER_EXIT_CODE_DISCONNECTED 1000

struct doveadm_server;
struct server_connection;
struct ssl_iostream;

typedef void server_cmd_callback_t(int exit_code, void *context);

int server_connection_create(struct doveadm_server *server,
			     struct server_connection **conn_r);
void server_connection_destroy(struct server_connection **conn);

/* Return the server given to create() */
struct doveadm_server *
server_connection_get_server(struct server_connection *conn);

void server_connection_cmd(struct server_connection *conn, const char *line,
			   server_cmd_callback_t *callback, void *context);
/* Returns TRUE if no command is being processed */
bool server_connection_is_idle(struct server_connection *conn);

/* Extract iostreams from connection. Afterwards the server_connection simply
   waits for itself to be destroyed. */
void server_connection_extract(struct server_connection *conn,
			       struct istream **istream_r,
			       struct ostream **ostream_r,
			       struct ssl_iostream **ssl_iostream_r);

#endif
