/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "network.h"
#include "iobuffer.h"
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
	IOBuffer *inbuf, *outbuf;
        AuthRequestType type;
};

static AuthInitData auth_init_data;
static LoginConnection *connections;

static void request_callback(AuthReplyData *reply, const unsigned char *data,
			     void *user_data)
{
	LoginConnection *conn = user_data;

	i_assert(reply->data_size <= AUTH_MAX_REPLY_DATA_SIZE);

	if (io_buffer_send(conn->outbuf, reply, sizeof(AuthReplyData)) < 0)
		login_connection_destroy(conn);
	else if (reply->data_size > 0) {
		if (io_buffer_send(conn->outbuf, data, reply->data_size) < 0)
			login_connection_destroy(conn);
	}
}

static void login_input(void *user_data, int fd __attr_unused__,
			IO io __attr_unused__)
{
	LoginConnection *conn  = user_data;
        unsigned char *data;
	unsigned int size;

	switch (io_buffer_read(conn->inbuf)) {
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

	data = io_buffer_get_data(conn->inbuf, &size);
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
		conn->inbuf->skip += sizeof(request);

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

		conn->inbuf->skip += sizeof(request) + request.data_size;

		/* we have a full continued request */
		auth_continue_request(&request, data + sizeof(request),
				      request_callback, conn);
		conn->type = AUTH_REQUEST_NONE;
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
	conn->inbuf = io_buffer_create(fd, default_pool,
				       IO_PRIORITY_DEFAULT, MAX_INBUF_SIZE);
	conn->outbuf = io_buffer_create(fd, default_pool,
					IO_PRIORITY_DEFAULT, MAX_OUTBUF_SIZE);
	conn->io = io_add(fd, IO_READ, login_input, conn);
	conn->type = AUTH_REQUEST_NONE;

	conn->next = connections;
	connections = conn;

	if (io_buffer_send(conn->outbuf, &auth_init_data,
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

	io_buffer_close(conn->inbuf);
	io_buffer_close(conn->outbuf);

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
