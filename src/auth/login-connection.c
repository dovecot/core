/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "hash.h"
#include "safe-memset.h"
#include "mech.h"
#include "login-connection.h"

#include <stdlib.h>
#include <syslog.h>

#define MAX_INBUF_SIZE \
	(sizeof(struct auth_login_request_continue) + \
	 AUTH_LOGIN_MAX_REQUEST_DATA_SIZE)
#define MAX_OUTBUF_SIZE (1024*50)

static struct timeout *to;
static struct auth_login_handshake_output handshake_output;
static struct login_connection *connections;

static void login_connection_unref(struct login_connection *conn);

static void request_callback(struct auth_login_reply *reply,
			     const void *data, struct login_connection *conn)
{
	ssize_t ret;

	ret = o_stream_send(conn->output, reply, sizeof(*reply));
	if ((size_t)ret == sizeof(*reply)) {
		if (reply->data_size == 0) {
			/* all sent */
			login_connection_unref(conn);
			return;
		}

		ret = o_stream_send(conn->output, data, reply->data_size);
		if ((size_t)ret == reply->data_size) {
			/* all sent */
			login_connection_unref(conn);
			return;
		}
	}

	if (ret >= 0)
		i_warning("Transmit buffer full for login process, killing it");

	login_connection_destroy(conn);
	login_connection_unref(conn);
}

struct login_connection *login_connection_lookup(unsigned int pid)
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
        struct auth_login_handshake_input rec;
        unsigned char *data;
	size_t size;

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(struct auth_login_handshake_input))
		return;

	/* Don't just cast because of alignment issues. */
	memcpy(&rec, data, sizeof(rec));
	i_stream_skip(conn->input, sizeof(rec));

	if (rec.pid == 0) {
		i_error("BUG: login said it's PID 0");
		login_connection_destroy(conn);
	} else if (login_connection_lookup(rec.pid) != NULL) {
		/* well, it might have just reconnected very fast .. although
		   there's not much reason for it. */
		i_error("BUG: login gave a PID of existing connection");
		login_connection_destroy(conn);
	} else {
		conn->pid = rec.pid;
		if (verbose_debug) {
			i_info("Login process %d sent handshake: PID %s",
			       conn->fd, dec2str(conn->pid));
		}
	}
}

static void login_input_request(struct login_connection *conn)
{
        enum auth_login_request_type type;
        unsigned char *data;
	size_t size;

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(type))
		return;

	/* note that we can't directly cast the received data pointer into
	   structures, as it may not be aligned properly. */
	memcpy(&type, data, sizeof(type));

	if (type == AUTH_LOGIN_REQUEST_NEW) {
		struct auth_login_request_new request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		i_stream_skip(conn->input, sizeof(request));

		/* we have a full init request */
		conn->refcount++;
		mech_request_new(conn, &request, request_callback);
	} else if (type == AUTH_LOGIN_REQUEST_CONTINUE) {
                struct auth_login_request_continue request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		if (size < sizeof(request) + request.data_size)
			return;

		i_stream_skip(conn->input, sizeof(request) + request.data_size);

		/* we have a full continued request */
		conn->refcount++;
		mech_request_continue(conn, &request, data + sizeof(request),
				      request_callback);

		/* clear any sensitive data from memory */
		safe_memset(data + sizeof(request), 0, request.data_size);
	} else {
		/* unknown request */
		i_error("BUG: login sent us unknown request %u", type);
		login_connection_destroy(conn);
	}
}

static void login_input(void *context)
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
		i_error("BUG: login sent us more than %d bytes of data",
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

	if (verbose_debug)
		i_info("Login process %d connected", fd);

	conn = i_new(struct login_connection, 1);
	conn->refcount = 1;

	conn->fd = fd;
	conn->input = i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE,
					   FALSE);
	conn->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					    FALSE);
	conn->io = io_add(fd, IO_READ, login_input, conn);

	conn->pool = pool_alloconly_create("auth_request hash", 10240);
	conn->auth_requests = hash_create(default_pool, conn->pool,
					  0, NULL, NULL);

	conn->next = connections;
	connections = conn;

	if (o_stream_send(conn->output, &handshake_output,
			  sizeof(handshake_output)) < 0) {
		login_connection_destroy(conn);
		conn = NULL;
	}

	return conn;
}

static void auth_request_hash_destroy(void *key __attr_unused__, void *value,
				      void *context __attr_unused__)
{
	struct auth_request *auth_request = value;

	auth_request->auth_free(auth_request);
}

void login_connection_destroy(struct login_connection *conn)
{
	struct login_connection **pos;

	if (conn->fd == -1)
		return;

	if (verbose_debug)
		i_info("Login process %d disconnected", conn->fd);

	for (pos = &connections; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

	i_stream_close(conn->input);
	o_stream_close(conn->output);

	io_remove(conn->io);
	net_disconnect(conn->fd);
	conn->fd = -1;

        login_connection_unref(conn);
}

static void login_connection_unref(struct login_connection *conn)
{
	if (--conn->refcount > 0)
		return;

	hash_foreach(conn->auth_requests, auth_request_hash_destroy, NULL);
	hash_destroy(conn->auth_requests);

	i_stream_unref(conn->input);
	o_stream_unref(conn->output);

	pool_unref(conn->pool);
	i_free(conn);
}

static void auth_request_hash_timeout_check(void *key __attr_unused__,
					    void *value, void *context)
{
	struct login_connection *conn = context;
	struct auth_request *auth_request = value;

	if (auth_request->created + AUTH_REQUEST_TIMEOUT < ioloop_time) {
		i_warning("Login process has too old (%us) requests, "
			  "killing it.",
			  (unsigned int)(ioloop_time - auth_request->created));

		login_connection_destroy(conn);
		hash_foreach_stop();
	}
}

static void request_timeout(void *context __attr_unused__)
{
	struct login_connection *conn;

	for (conn = connections; conn != NULL; conn = conn->next) {
		hash_foreach(conn->auth_requests,
			     auth_request_hash_timeout_check, conn);
	}
}

void login_connections_init(void)
{
	const char *env;
	unsigned int pid;

	env = getenv("AUTH_PROCESS");
	if (env == NULL)
		i_fatal("AUTH_PROCESS environment is unset");

	pid = atoi(env);
	if (pid == 0)
		i_fatal("AUTH_PROCESS can't be 0");

	memset(&handshake_output, 0, sizeof(handshake_output));
	handshake_output.pid = pid;
	handshake_output.auth_mechanisms = auth_mechanisms;

	connections = NULL;
	to = timeout_add(5000, request_timeout, NULL);
}

void login_connections_deinit(void)
{
	struct login_connection *next;

	while (connections != NULL) {
		next = connections->next;
		login_connection_destroy(connections);
		connections = next;
	}

	timeout_remove(to);
}
