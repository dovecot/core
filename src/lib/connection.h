#ifndef CONNECTION_H
#define CONNECTION_H

#include "net.h"

struct connection;

enum connection_behavior {
	CONNECTION_BEHAVIOR_DESTROY = 0,
	CONNECTION_BEHAVIOR_ALLOW
};

enum connection_disconnect_reason {
	/* not disconnected yet */
	CONNECTION_DISCONNECT_NOT = 0,
	/* normal requested disconnection */
	CONNECTION_DISCONNECT_DEINIT,
	/* input buffer full */
	CONNECTION_DISCONNECT_BUFFER_FULL,
	/* connection got disconnected */
	CONNECTION_DISCONNECT_CONN_CLOSED,
	/* connect() timed out */
	CONNECTION_DISCONNECT_CONNECT_TIMEOUT,
	/* remote didn't send input */
	CONNECTION_DISCONNECT_IDLE_TIMEOUT
};

struct connection_vfuncs {
	void (*destroy)(struct connection *conn);
	/* For UNIX socket clients this gets called immediately with
	   success=TRUE, for IP connections it gets called later:

	   If connect() fails, sets success=FALSE and errno. Streams aren't
	   initialized in that situation either. destroy() is called after
	   the callback. */
	void (*client_connected)(struct connection *conn, bool success);

	/* implement one of the input*() methods.
	   They return 0 = ok, -1 = error, disconnect the client */
	void (*input)(struct connection *conn);
	int (*input_line)(struct connection *conn, const char *line);
	int (*input_args)(struct connection *conn, const char *const *args);
};

struct connection_settings {
	const char *service_name_in;
	const char *service_name_out;
	unsigned int major_version, minor_version;

	unsigned int client_connect_timeout_msecs;
	unsigned int input_idle_timeout_secs;

	size_t input_max_size;
	size_t output_max_size;
	enum connection_behavior input_full_behavior;

	bool client;
	bool dont_send_version;
};

struct connection {
	struct connection *prev, *next;
	struct connection_list *list;

	char *name;
	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct timeout *to;
	time_t last_input;

	/* for IP client: */
	struct ip_addr ip;
	unsigned int port;

	/* received minor version */
	unsigned int minor_version;

	enum connection_disconnect_reason disconnect_reason;

	unsigned int version_received:1;
};

struct connection_list {
	struct connection *connections;
	unsigned int connections_count;

	struct connection_settings set;
	struct connection_vfuncs v;
};

void connection_init_server(struct connection_list *list,
			    struct connection *conn, const char *name,
			    int fd_in, int fd_out);
void connection_init_client_ip(struct connection_list *list,
			       struct connection *conn,
			       const struct ip_addr *ip, unsigned int port);
void connection_init_client_unix(struct connection_list *list,
				 struct connection *conn, const char *path);

int connection_client_connect(struct connection *conn);

void connection_disconnect(struct connection *conn);
void connection_deinit(struct connection *conn);

/* Returns -1 = disconnected, 0 = nothing new, 1 = something new.
   If input_full_behavior is ALLOW, may return also -2 = buffer full. */
int connection_input_read(struct connection *conn);
/* Verify that VERSION input matches what we expect. */
int connection_verify_version(struct connection *conn, const char *const *args);

/* Returns human-readable reason for why connection was disconnected. */
const char *connection_disconnect_reason(struct connection *conn);

void connection_switch_ioloop(struct connection *conn);

struct connection_list *
connection_list_init(const struct connection_settings *set,
		     const struct connection_vfuncs *vfuncs);
void connection_list_deinit(struct connection_list **list);

void connection_input_default(struct connection *conn);
int connection_input_line_default(struct connection *conn, const char *line);

#endif
