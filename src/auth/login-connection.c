/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "safe-memset.h"
#include "cookie.h"
#include "login-connection.h"

#include <stdlib.h>
#include <syslog.h>

#define MAX_INBUF_SIZE \
	(sizeof(struct auth_continued_request_data) + \
	 AUTH_MAX_REQUEST_DATA_SIZE)
#define MAX_OUTBUF_SIZE \
	(10 * (sizeof(struct auth_reply_data) + AUTH_MAX_REPLY_DATA_SIZE))

struct login_connection {
	struct login_connection *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int pid;
	enum auth_request_type type;
};

static struct auth_init_data auth_init_data;
static struct login_connection *connections;

static void request_callback(struct auth_reply_data *reply,
			     const void *data, void *context)
{
	struct login_connection *conn = context;

	i_assert(reply->data_size <= AUTH_MAX_REPLY_DATA_SIZE);

	if (o_stream_send(conn->output, reply, sizeof(*reply)) < 0)
		login_connection_destroy(conn);
	else if (reply->data_size > 0) {
		if (o_stream_send(conn->output, data, reply->data_size) < 0)
			login_connection_destroy(conn);
	}
}

static struct login_connection *login_find_pid(unsigned int pid)
{
	struct login_connection *conn;

	for (conn = connections; conn != NULL; conn = conn->next) {
		if (conn->pid == pid)
			return conn;
	}

	return NULL;
}

static void login_input_handshake(struct login_connection *conn)
{
        struct client_auth_init_data rec;
        unsigned char *data;
	size_t size;

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(struct client_auth_init_data))
		return;

	/* Don't just cast because of alignment issues. */
	memcpy(&rec, data, sizeof(rec));
	i_stream_skip(conn->input, sizeof(rec));

	if (rec.pid == 0) {
		i_error("BUG: imap-login said it's PID 0");
		login_connection_destroy(conn);
	} else if (login_find_pid(rec.pid) != NULL) {
		/* well, it might have just reconnected very fast .. although
		   there's not much reason for it. */
		i_error("BUG: imap-login gave a PID of existing connection");
		login_connection_destroy(conn);
	} else {
		conn->pid = rec.pid;
		if (verbose) {
			i_info("Login process %d sent handshake: PID %s",
			       conn->fd, dec2str(conn->pid));
		}
	}
}

static void login_input_request(struct login_connection *conn)
{
        unsigned char *data;
	size_t size;

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(enum auth_request_type))
		return;

	/* note that we can't directly cast the received data pointer into
	   structures, as it may not be aligned properly. */
	if (conn->type == AUTH_REQUEST_NONE) {
		/* get the request type */
		memcpy(&conn->type, data, sizeof(enum auth_request_type));
	}

	if (conn->type == AUTH_REQUEST_INIT) {
		struct auth_init_request_data request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		i_stream_skip(conn->input, sizeof(request));

		/* we have a full init request */
		auth_init_request(conn->pid, &request, request_callback, conn);
		conn->type = AUTH_REQUEST_NONE;
	} else if (conn->type == AUTH_REQUEST_CONTINUE) {
                struct auth_continued_request_data request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		if (size < sizeof(request) + request.data_size)
			return;

		i_stream_skip(conn->input, sizeof(request) + request.data_size);

		/* we have a full continued request */
		auth_continue_request(conn->pid, &request,
				      data + sizeof(request),
				      request_callback, conn);
		conn->type = AUTH_REQUEST_NONE;

		/* clear any sensitive data from memory */
		safe_memset(data + sizeof(request), 0, request.data_size);
	} else {
		/* unknown request */
		i_error("BUG: imap-login sent us unknown request %u",
			conn->type);
		login_connection_destroy(conn);
	}
}

static void login_input(void *context, int fd __attr_unused__,
			struct io *io __attr_unused__)
{
	struct login_connection *conn  = context;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		login_connection_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: imap-login sent us more than %d bytes of data",
			(int)MAX_INBUF_SIZE);
		login_connection_destroy(conn);
		return;
	}

	if (conn->pid == 0)
		login_input_handshake(conn);
	else
		login_input_request(conn);
}

struct login_connection *login_connection_create(int fd)
{
	struct login_connection *conn;

	if (verbose)
		i_info("Login process %d connected", fd);

	conn = i_new(struct login_connection, 1);

	conn->fd = fd;
	conn->input = i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE,
					   FALSE);
	conn->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					    IO_PRIORITY_DEFAULT, FALSE);
	conn->io = io_add(fd, IO_READ, login_input, conn);
	conn->type = AUTH_REQUEST_NONE;

	conn->next = connections;
	connections = conn;

	if (o_stream_send(conn->output, &auth_init_data,
			  sizeof(auth_init_data)) < 0) {
		login_connection_destroy(conn);
		conn = NULL;
	}

	return conn;
}

void login_connection_destroy(struct login_connection *conn)
{
	struct login_connection **pos;

	if (verbose)
		i_info("Login process %d disconnected", conn->fd);

	for (pos = &connections; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

	cookies_remove_login_pid(conn->pid);

	i_stream_unref(conn->input);
	o_stream_unref(conn->output);

	io_remove(conn->io);
	net_disconnect(conn->fd);
	i_free(conn);
}

void login_connections_init(void)
{
	const char *env;

	env = getenv("AUTH_PROCESS");
	if (env == NULL)
		i_fatal("AUTH_PROCESS environment is unset");

	memset(&auth_init_data, 0, sizeof(auth_init_data));
	auth_init_data.auth_process = atoi(env);
	auth_init_data.auth_mechanisms = auth_mechanisms;

	connections = NULL;
}

void login_connections_deinit(void)
{
	struct login_connection *next;

	while (connections != NULL) {
		next = connections->next;
		login_connection_destroy(connections);
		connections = next;
	}
}
