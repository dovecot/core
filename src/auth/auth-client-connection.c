/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "hash.h"
#include "safe-memset.h"
#include "mech.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdlib.h>
#include <syslog.h>

#define MAX_INBUF_SIZE \
	(sizeof(struct auth_client_request_continue) + \
	 AUTH_CLIENT_MAX_REQUEST_DATA_SIZE)
#define MAX_OUTBUF_SIZE (1024*50)

static void auth_client_connection_unref(struct auth_client_connection *conn);

static void request_callback(struct auth_client_request_reply *reply,
			     const void *data,
			     struct auth_client_connection *conn)
{
	ssize_t ret;

	ret = o_stream_send(conn->output, reply, sizeof(*reply));
	if ((size_t)ret == sizeof(*reply)) {
		if (reply->data_size == 0) {
			/* all sent */
			auth_client_connection_unref(conn);
			return;
		}

		ret = o_stream_send(conn->output, data, reply->data_size);
		if ((size_t)ret == reply->data_size) {
			/* all sent */
			auth_client_connection_unref(conn);
			return;
		}
	}

	if (ret >= 0) {
		i_warning("Auth client %u: Transmit buffer full, killing it",
			  conn->pid);
	}

	auth_client_connection_destroy(conn);
	auth_client_connection_unref(conn);
}

struct auth_client_connection *
auth_client_connection_lookup(struct auth_master_connection *master,
			      unsigned int pid)
{
	struct auth_client_connection *conn;

	for (conn = master->clients; conn != NULL; conn = conn->next) {
		if (conn->pid == pid)
			return conn;
	}

	return NULL;
}

static void auth_client_input_handshake(struct auth_client_connection *conn)
{
        struct auth_client_handshake_request rec;
        unsigned char *data;
	size_t size;

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(rec))
		return;

	/* Don't just cast because of alignment issues. */
	memcpy(&rec, data, sizeof(rec));
	i_stream_skip(conn->input, sizeof(rec));

	if (rec.client_pid == 0) {
		i_error("BUG: Auth client said it's PID 0");
		auth_client_connection_destroy(conn);
	} else if (auth_client_connection_lookup(conn->master,
						 rec.client_pid) != NULL) {
		/* well, it might have just reconnected very fast .. although
		   there's not much reason for it. */
		i_error("BUG: Auth client gave a PID %u of existing connection",
			rec.client_pid);
		auth_client_connection_destroy(conn);
	} else {
		conn->pid = rec.client_pid;
	}
}

static void auth_client_input_request(struct auth_client_connection *conn)
{
        enum auth_client_request_type type;
        unsigned char *data;
	size_t size;

	data = i_stream_get_modifyable_data(conn->input, &size);
	if (size < sizeof(type))
		return;

	/* note that we can't directly cast the received data pointer into
	   structures, as it may not be aligned properly. */
	memcpy(&type, data, sizeof(type));

	if (type == AUTH_CLIENT_REQUEST_NEW) {
		struct auth_client_request_new request;

		if (size < sizeof(request))
			return;

		memcpy(&request, data, sizeof(request));
		i_stream_skip(conn->input, sizeof(request));

		/* we have a full init request */
		conn->refcount++;
		mech_request_new(conn, &request, request_callback);
	} else if (type == AUTH_CLIENT_REQUEST_CONTINUE) {
                struct auth_client_request_continue request;

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
		i_error("BUG: Auth client %u sent us unknown request %u",
			conn->pid, type);
		auth_client_connection_destroy(conn);
	}
}

static void auth_client_input(void *context)
{
	struct auth_client_connection *conn  = context;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_client_connection_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth client %u sent us more than %d bytes",
			conn->pid, (int)MAX_INBUF_SIZE);
		auth_client_connection_destroy(conn);
		return;
	}

	if (conn->pid == 0)
		auth_client_input_handshake(conn);
	else
		auth_client_input_request(conn);
}

struct auth_client_connection *
auth_client_connection_create(struct auth_master_connection *master, int fd)
{
	struct auth_client_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("Auth client", 4096);
	conn = p_new(pool, struct auth_client_connection, 1);
	conn->pool = pool;
	conn->master = master;
	conn->refcount = 1;

	conn->fd = fd;
	conn->input = i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE,
					   FALSE);
	conn->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					    FALSE);
	conn->io = io_add(fd, IO_READ, auth_client_input, conn);

	conn->auth_requests = hash_create(default_pool, conn->pool,
					  0, NULL, NULL);

	conn->next = master->clients;
	master->clients = conn;

	if (o_stream_send(conn->output, &master->handshake_reply,
			  sizeof(master->handshake_reply)) < 0) {
		auth_client_connection_destroy(conn);
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

void auth_client_connection_destroy(struct auth_client_connection *conn)
{
	struct auth_client_connection **pos;

	if (conn->fd == -1)
		return;

	for (pos = &conn->master->clients; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

	i_stream_close(conn->input);
	o_stream_close(conn->output);

	io_remove(conn->io);
	conn->io = 0;

	net_disconnect(conn->fd);
	conn->fd = -1;

	conn->master = NULL;
        auth_client_connection_unref(conn);
}

static void auth_client_connection_unref(struct auth_client_connection *conn)
{
	if (--conn->refcount > 0)
		return;

	hash_foreach(conn->auth_requests, auth_request_hash_destroy, NULL);
	hash_destroy(conn->auth_requests);

	i_stream_unref(conn->input);
	o_stream_unref(conn->output);

	pool_unref(conn->pool);
}

static void auth_request_hash_timeout_check(void *key __attr_unused__,
					    void *value, void *context)
{
	struct auth_client_connection *conn = context;
	struct auth_request *auth_request = value;

	if (auth_request->created + AUTH_REQUEST_TIMEOUT < ioloop_time) {
		i_warning("Login process has too old (%us) requests, "
			  "killing it.",
			  (unsigned int)(ioloop_time - auth_request->created));

		auth_client_connection_destroy(conn);
		hash_foreach_stop();
	}
}

static void request_timeout(void *context __attr_unused__)
{
        struct auth_master_connection *master = context;
	struct auth_client_connection *conn;

	for (conn = master->clients; conn != NULL; conn = conn->next) {
		conn->refcount++;
		hash_foreach(conn->auth_requests,
			     auth_request_hash_timeout_check, conn);
		auth_client_connection_unref(conn);
	}
}

void auth_client_connections_init(struct auth_master_connection *master)
{
	master->handshake_reply.server_pid = master->pid;
	master->handshake_reply.auth_mechanisms = auth_mechanisms;

	master->to_clients = timeout_add(5000, request_timeout, master);
}

void auth_client_connections_deinit(struct auth_master_connection *master)
{
	struct auth_client_connection *next;

	while (master->clients != NULL) {
		next = master->clients->next;
		auth_client_connection_destroy(master->clients);
		master->clients = next;
	}

	timeout_remove(master->to_clients);
	master->to_clients = NULL;
}
