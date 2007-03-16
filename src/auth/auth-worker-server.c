/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "auth-request.h"
#include "auth-worker-client.h"
#include "auth-worker-server.h"

#include <stdlib.h>
#include <unistd.h>

#define AUTH_WORKER_MAX_OUTBUF_SIZE 10240
#define AUTH_WORKER_MAX_IDLE_TIME (60*30)

struct auth_worker_request {
	unsigned int id;
	struct auth_request *auth_request;
        auth_worker_callback_t *callback;
};

struct auth_worker_connection {
	int fd;

	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int id_counter;
        buffer_t *requests; /* struct auth_worker_request[] */

	time_t last_used;
	unsigned int request_count;
};

static buffer_t *connections = NULL;
static unsigned int idle_count;
static unsigned int auth_workers_max;

static char *worker_socket_path;
static struct timeout *to;

static void worker_input(struct auth_worker_connection *conn);

static struct auth_worker_connection *auth_worker_create(void)
{
	struct auth_worker_connection *conn;
	int fd, try;

	if (connections->used / sizeof(conn) >= auth_workers_max)
		return NULL;

	for (try = 0;; try++) {
		fd = net_connect_unix(worker_socket_path);
		if (fd >= 0)
			break;

		if (errno == EAGAIN || errno == ECONNREFUSED) {
			/* we're busy. */
		} else if (errno == ENOENT) {
			/* master didn't yet create it? */
		} else {
			i_fatal("net_connect_unix(%s) failed: %m",
				worker_socket_path);
		}

		if (try == 5) {
			i_fatal("net_connect_unix(%s) "
				"failed after %d tries: %m",
				worker_socket_path, try);
		}

		/* not created yet? try again */
		sleep(1);
	}

	conn = i_new(struct auth_worker_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_file(fd, default_pool,
					   AUTH_WORKER_MAX_LINE_LENGTH, FALSE);
	conn->output =
		o_stream_create_file(fd, default_pool, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_READ, worker_input, conn);
	conn->requests = buffer_create_dynamic(default_pool, 128);

	idle_count++;

	buffer_append(connections, &conn, sizeof(conn));
	return conn;
}

static void auth_worker_destroy(struct auth_worker_connection *conn)
{
	struct auth_worker_connection **connp;
	struct auth_worker_request *request;
	size_t i, size;
	const char *reply;

	connp = buffer_get_modifiable_data(connections, &size);
	size /= sizeof(*connp);

	for (i = 0; i < size; i++) {
		if (connp[i] == conn) {
			buffer_delete(connections, i * sizeof(*connp),
				      sizeof(*connp));
			break;
		}
	}

	if (conn->request_count == 0)
		idle_count--;

	/* abort all pending requests */
	request = buffer_get_modifiable_data(conn->requests, &size);
	size /= sizeof(*request);

	reply = t_strdup_printf("FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE);
	for (i = 0; i < size; i++) {
		if (request[i].id != 0) {
			request[i].callback(request[i].auth_request, reply);
			auth_request_unref(&request[i].auth_request);
		}
	}


	buffer_free(conn->requests);
	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);

	if (close(conn->fd) < 0)
		i_error("close(auth worker) failed: %m");
	i_free(conn);
}

static struct auth_worker_request *
auth_worker_request_lookup(struct auth_worker_connection *conn,
			   unsigned int id)
{
	struct auth_worker_request *request;
	size_t i, size;

	request = buffer_get_modifiable_data(conn->requests, &size);
	size /= sizeof(*request);

	for (i = 0; i < size; i++) {
		if (request[i].id == id)
			return &request[i];
	}

	return NULL;
}

static struct auth_worker_connection *auth_worker_find_free(void)
{
	struct auth_worker_connection **conn, *best;
	size_t i, size, outbuf_size, best_size;

	conn = buffer_get_modifiable_data(connections, &size);
	size /= sizeof(*conn);

	if (idle_count > 0) {
		/* there exists at least one idle connection, use it */
		for (i = 0; i < size; i++) {
			if (conn[i]->request_count == 0)
				return conn[i];
		}
		i_unreached();
	}

	/* first the connection with least data in output buffer */
	best = NULL;
	best_size = (size_t)-1;
	for (i = 0; i < size; i++) {
		outbuf_size = o_stream_get_buffer_used_size(conn[i]->output);
		if (outbuf_size < best_size) {
			best = conn[i];
			best_size = outbuf_size;
		}
	}

	return best;
}

static void auth_worker_handle_request(struct auth_worker_connection *conn,
				       struct auth_worker_request *request,
				       const char *line)
{
	request->callback(request->auth_request, line);
	auth_request_unref(&request->auth_request);

	/* mark the record empty so it can be used for future requests */
	memset(request, 0, sizeof(*request));

	/* update counters */
	conn->request_count--;
	if (conn->request_count == 0)
		idle_count++;
}

static void worker_input(struct auth_worker_connection *conn)
{
	struct auth_worker_request *request;
	const char *line, *id_str;
	unsigned int id;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_worker_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth worker sent us more than %d bytes",
			(int)AUTH_WORKER_MAX_LINE_LENGTH);
		auth_worker_destroy(conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		id_str = line;
		line = strchr(line, '\t');
		if (line == NULL)
			continue;

		t_push();
		id = (unsigned int)strtoul(t_strcut(id_str, '\t'), NULL, 10);
		request = auth_worker_request_lookup(conn, id);
		t_pop();

		if (request != NULL)
			auth_worker_handle_request(conn, request, line + 1);
	}
}

static struct auth_worker_request *
auth_worker_request_get(struct auth_worker_connection *conn)
{
        struct auth_worker_request *request;
	size_t i, size;

	request = buffer_get_modifiable_data(conn->requests, &size);
	size /= sizeof(*request);

	for (i = 0; i < size; i++) {
		if (request[i].id == 0)
			return &request[i];
	}

	return buffer_append_space_unsafe(conn->requests, sizeof(*request));
}

void auth_worker_call(struct auth_request *auth_request, const char *data,
		      auth_worker_callback_t *callback)
{
	struct auth_worker_connection *conn;
	struct auth_worker_request *request;
	const char *reply;
	struct const_iovec iov[3];

	conn = auth_worker_find_free();
	if (conn == NULL) {
		/* no connections currently. can happen if all have been
		   idle for last 10 minutes. create a new one. */
		conn = auth_worker_create();
		if (conn == NULL) {
			auth_request_log_error(auth_request, "worker-server",
				"Couldn't create new auth worker");
			reply = t_strdup_printf("FAIL\t%d",
						PASSDB_RESULT_INTERNAL_FAILURE);
			callback(auth_request, reply);
			return;
		}
	}

	iov[0].iov_base = t_strdup_printf("%d\t", ++conn->id_counter);
	iov[0].iov_len = strlen(iov[0].iov_base);
	iov[1].iov_base = data;
	iov[1].iov_len = strlen(data);
	iov[2].iov_base = "\n";
	iov[2].iov_len = 1;

	if (o_stream_get_buffer_used_size(conn->output) +
	    iov[0].iov_len + iov[1].iov_len + 1 > AUTH_WORKER_MAX_OUTBUF_SIZE) {
		auth_request_log_error(auth_request, "worker-server",
				       "All auth workers are busy");
		reply = t_strdup_printf("FAIL\t%d",
					PASSDB_RESULT_INTERNAL_FAILURE);
		callback(auth_request, reply);
		return;
	}

	/* find an empty request */
	request = auth_worker_request_get(conn);
	request->id = conn->id_counter;
	request->auth_request = auth_request;
	request->callback = callback;
	auth_request_ref(auth_request);

	o_stream_sendv(conn->output, iov, 3);

	if (idle_count == 0) {
		/* this request was queued, we need new workers */
		auth_worker_create();
	}

	conn->last_used = ioloop_time;
	if (conn->request_count++ == 0)
		idle_count--;
}

static void auth_worker_timeout(void *context __attr_unused__)
{
	struct auth_worker_connection **conn;
	size_t i, size;

	conn = buffer_get_modifiable_data(connections, &size);
	size /= sizeof(*conn);

	if (idle_count <= 1)
		return;

	/* remove connections which we haven't used for a long time.
	   this works because auth_worker_find_free() always returns the
	   first free connection. */
	for (i = 0; i < size; i++) {
		if (conn[i]->last_used +
		    AUTH_WORKER_MAX_IDLE_TIME < ioloop_time) {
			/* remove just one. easier.. */
			auth_worker_destroy(conn[i]);
			break;
		}
	}
}

void auth_worker_server_init(void)
{
	const char *env;

	if (connections != NULL) {
		/* already initialized */
		return;
	}

	env = getenv("AUTH_WORKER_PATH");
	if (env == NULL)
		i_fatal("AUTH_WORKER_PATH environment not set");
	worker_socket_path = i_strdup(env);

	env = getenv("AUTH_WORKER_MAX_COUNT");
	if (env == NULL)
		i_fatal("AUTH_WORKER_MAX_COUNT environment not set");
	auth_workers_max = atoi(env);

	connections = buffer_create_dynamic(default_pool,
		sizeof(struct auth_worker_connection) * 16);
	to = timeout_add(1000 * 60, auth_worker_timeout, NULL);

	auth_worker_create();
}

void auth_worker_server_deinit(void)
{
	struct auth_worker_connection **connp;

	if (connections == NULL)
		return;

	while (connections->used > 0) {
		connp = buffer_get_modifiable_data(connections, NULL);
		auth_worker_destroy(*connp);
	}
	buffer_free(connections);
	connections = NULL;

	timeout_remove(&to);
	i_free(worker_socket_path);
}
