#ifndef CONNECTION_H
#define CONNECTION_H

#include "net.h"

struct ioloop;
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
	CONNECTION_DISCONNECT_IDLE_TIMEOUT,
	/* handshake failed */
	CONNECTION_DISCONNECT_HANDSHAKE_FAILED,
};

struct connection_vfuncs {
	void (*destroy)(struct connection *conn);
	/* For UNIX socket clients this gets called immediately (unless
	   delayed_unix_client_connected_callback=TRUE) with success=TRUE,
	   for IP connections it gets called later:

	   If connect() fails, sets success=FALSE and errno. Streams aren't
	   initialized in that situation either. destroy() is called after
	   the callback. */
	void (*client_connected)(struct connection *conn, bool success);

	/* implement one of the input*() methods.
	   They return 1 = ok, continue. 0 = ok, but stop processing more
	   lines, -1 = error, disconnect the client. */
	void (*input)(struct connection *conn);
	int (*input_line)(struct connection *conn, const char *line);
	int (*input_args)(struct connection *conn, const char *const *args);

	/* handshake functions. Defaults to version checking.
	   must return 1 when handshake is completed, otherwise return 0.
	   return -1 to indicate error and disconnect client.

	   if you implement this, remember to call connection_verify_version
	   yourself, otherwise you end up with assert crash.

	   these will not be called if you implement `input` virtual function.
	*/
	int (*handshake)(struct connection *conn);
	int (*handshake_line)(struct connection *conn, const char *line);
	int (*handshake_args)(struct connection *conn, const char *const *args);

	/* Called when the connection handshake is ready. */
	void (*handshake_ready)(struct connection *conn);

	/* Called when input_idle_timeout_secs is reached, defaults to disconnect */
	void (*idle_timeout)(struct connection *conn);
	/* Called when client_connect_timeout_msecs is reached, defaults to disconnect */
	void (*connect_timeout)(struct connection *conn);
};

struct connection_settings {
	const char *service_name_in;
	const char *service_name_out;
	unsigned int major_version, minor_version;

	unsigned int client_connect_timeout_msecs;
	unsigned int input_idle_timeout_secs;

	/* These need to be non-zero for corresponding stream to
	   be created. */
	size_t input_max_size;
	size_t output_max_size;
	enum connection_behavior input_full_behavior;

	/* Set to TRUE if this is a client */
	bool client;

	/* Set to TRUE if version should not be sent */
	bool dont_send_version;
	/* By default when only input_args() is used, or when
	   connection_input_line_default() is used, empty lines aren't allowed
	   since it would result in additional args[0] == NULL check. Setting
	   this to TRUE passes it through instead of logging an error. */
	bool allow_empty_args_input;
	/* Don't call client_connected() immediately on
	   connection_client_connect() with UNIX sockets. This is mainly
	   to make the functionality identical with inet sockets, which may
	   simplify the calling code. */
	bool delayed_unix_client_connected_callback;
	/* If connect() to UNIX socket fails with EAGAIN, retry for this many
	   milliseconds before giving up (0 = try once) */
	unsigned int unix_client_connect_msecs;
	/* Turn on debug logging */
	bool debug;
};

struct connection {
	struct connection *prev, *next;
	struct connection_list *list;

	char *name;
	int fd_in, fd_out;
	struct ioloop *ioloop;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int input_idle_timeout_secs;
	struct timeout *to;
	time_t last_input;
	struct timeval last_input_tv;
	struct timeval connect_started;
	struct timeval connect_finished;

	/* set to parent event before calling init */
	struct event *event_parent;
	struct event *event;

	/* for IP client: */
	struct ip_addr ip, my_ip;
	in_port_t port;

	/* received minor version */
	unsigned int minor_version;

	/* handlers */
	struct connection_vfuncs v;

	enum connection_disconnect_reason disconnect_reason;

	bool version_received:1;
	bool handshake_received:1;
	bool unix_socket:1;
	bool disconnected:1;
};

struct connection_list {
	struct connection *connections;
	unsigned int connections_count;

	struct connection_settings set;
	struct connection_vfuncs v;
};

void connection_init(struct connection_list *list, struct connection *conn,
		     const char *name) ATTR_NULL(3);
void connection_init_server(struct connection_list *list,
			    struct connection *conn, const char *name,
			    int fd_in, int fd_out);
void connection_init_client_ip(struct connection_list *list,
			       struct connection *conn,
			       const struct ip_addr *ip, in_port_t port);
void connection_init_client_ip_from(struct connection_list *list,
				    struct connection *conn,
				    const struct ip_addr *ip, in_port_t port,
				    const struct ip_addr *my_ip) ATTR_NULL(5);
void connection_init_client_unix(struct connection_list *list,
				 struct connection *conn, const char *path);
void connection_init_client_fd(struct connection_list *list,
			       struct connection *conn, const char *name, int fd_int, int fd_out);
void connection_init_from_streams(struct connection_list *list,
			    struct connection *conn, const char *name,
			    struct istream *input, struct ostream *output);

int connection_client_connect(struct connection *conn);

/* Disconnects a connection */
void connection_disconnect(struct connection *conn);

/* Deinitializes a connection, calls disconnect */
void connection_deinit(struct connection *conn);

void connection_input_halt(struct connection *conn);
void connection_input_resume(struct connection *conn);

/* This needs to be called if the input/output streams are changed */
void connection_streams_changed(struct connection *conn);

/* Returns -1 = disconnected, 0 = nothing new, 1 = something new.
   If input_full_behavior is ALLOW, may return also -2 = buffer full. */
int connection_input_read(struct connection *conn);
/* Verify that VERSION input matches what we expect. */
int connection_verify_version(struct connection *conn,
			      const char *service_name,
			      unsigned int major_version,
			      unsigned int minor_version);

int connection_handshake_args_default(struct connection *conn,
				      const char *const *args);

/* Returns human-readable reason for why connection was disconnected. */
const char *connection_disconnect_reason(struct connection *conn);
/* Returns human-readable reason for why connection timed out,
   e.g. "No input for 10.023 secs". */
const char *connection_input_timeout_reason(struct connection *conn);

void connection_switch_ioloop_to(struct connection *conn,
				 struct ioloop *ioloop);
void connection_switch_ioloop(struct connection *conn);

struct connection_list *
connection_list_init(const struct connection_settings *set,
		     const struct connection_vfuncs *vfuncs);
void connection_list_deinit(struct connection_list **list);

void connection_input_default(struct connection *conn);
int connection_input_line_default(struct connection *conn, const char *line);

/* Change handlers, calls connection_input_halt and connection_input_resume */
void connection_set_handlers(struct connection *conn, const struct connection_vfuncs *vfuncs);
void connection_set_default_handlers(struct connection *conn);

#endif
