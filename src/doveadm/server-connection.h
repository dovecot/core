#ifndef SERVER_CONNECTION_H
#define SERVER_CONNECTION_H

#define SERVER_EXIT_CODE_DISCONNECTED 1000

struct doveadm_server;
struct server_connection;
struct ssl_iostream;

struct doveadm_server_reply {
	int exit_code;
	const char *error;
};

typedef void server_cmd_callback_t(const struct doveadm_server_reply *reply,
				   void *context);

/* Called when a field needs to be printed. If finished=FALSE, the next
   call will continue printing this same field. */
typedef void server_connection_print_t(const unsigned char *data,
				       size_t size, bool finished,
				       void *context);

int server_connection_create(struct doveadm_server *server,
			     struct server_connection **conn_r,
			     const char **error_r);

void server_connection_get_dest(struct server_connection *conn,
				struct ip_addr *ip_r, in_port_t *port_r);

void server_connection_set_print(struct server_connection *conn,
				 server_connection_print_t *callback,
				 void *context);
#define server_connection_set_print(conn, callback, context) \
	server_connection_set_print(conn, \
		(server_connection_print_t *)callback, \
		TRUE ? context : CALLBACK_TYPECHECK(callback, \
			void (*)(const unsigned char *, size_t, bool, typeof(context))))

void server_connection_cmd(struct server_connection *conn, int proxy_ttl,
			   const char *line, struct istream *cmd_input,
			   server_cmd_callback_t *callback, void *context);

/* Extract iostreams from connection. Afterwards the server_connection simply
   waits for itself to be destroyed. */
void server_connection_extract(struct server_connection *conn,
			       struct istream **istream_r,
			       struct ostream **ostream_r,
			       struct ssl_iostream **ssl_iostream_r);

#endif
