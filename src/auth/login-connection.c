/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "login-connection.h"

#include <stdlib.h>
#include <syslog.h>

#define MAX_INBUF_SIZE \
	(sizeof(AuthContinuedRequestData) + AUTH_MAX_REQUEST_DATA_SIZE)
#define MAX_OUTBUF_SIZE \
	(10 * (sizeof(AuthReplyData) + AUTH_MAX_REPLY_DATA_SIZE))

struct _LoginConnection {
	LoginConnection *next;

	int fd;
	IO io;
	IStream *input;
	OStream *output;
        AuthRequestType type;
};

static AuthInitData auth_init_data;
static LoginConnection *connections;

static void request_callback(AuthReplyData *reply, const unsigned char *data,
			     void *context)
{
	LoginConnection *conn = context;

	i_assert(reply->data_size <= AUTH_MAX_REPLY_DATA_SIZE);

	if (o_stream_send(conn->output, reply, sizeof(AuthReplyData)) < 0)
		login_connection_destroy(conn);
	else if (reply->data_size > 0) {
		if (o_stream_send(conn->output, data, reply->data_size) < 0)
			login_connection_destroy(conn);
	}
}

static void login_input(void *context, int fd __attr_unused__,
			IO io __attr_unused__)
{
	LoginConnection *conn  = context;
        unsigned char *data;
	size_t size;

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

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(AuthRequestType))
		return;

	/* note that we can't directly cast the received data pointer into
	   structures, as it may not be aligned properly. */
	if (conn->type == AUTH_REQUEST_NONE) {
		/* get the request type */
		memcpy(&conn->type, data, sizeof(AuthRequestType));
	}

	if (conn->type == AUTH_REQUEST_INIT) {
		AuthInitRequestData request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		i_stream_skip(conn->input, sizeof(request));

		/* we have a full init request */
		auth_init_request(&request, request_callback, conn);
		conn->type = AUTH_REQUEST_NONE;
	} else if (conn->type == AUTH_REQUEST_CONTINUE) {
                AuthContinuedRequestData request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		if (size < sizeof(request) + request.data_size)
			return;

		i_stream_skip(conn->input, sizeof(request) + request.data_size);

		/* we have a full continued request */
		auth_continue_request(&request, data + sizeof(request),
				      request_callback, conn);
		conn->type = AUTH_REQUEST_NONE;

		/* clear any sensitive data from memory */
		memset(data + sizeof(request), 0, request.data_size);
	} else {
		/* unknown request */
		i_error("BUG: imap-login sent us unknown request %u",
			conn->type);
		login_connection_destroy(conn);
	}
}

LoginConnection *login_connection_create(int fd)
{
	LoginConnection *conn;

	conn = i_new(LoginConnection, 1);

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

void login_connection_destroy(LoginConnection *conn)
{
	LoginConnection **pos;

	for (pos = &connections; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

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
	auth_init_data.auth_methods = auth_methods;

	connections = NULL;
}

void login_connections_deinit(void)
{
	LoginConnection *next;

	while (connections != NULL) {
		next = connections->next;
		login_connection_destroy(connections);
		connections = next;
	}
}
