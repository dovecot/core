/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
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
#define AUTH_WORKER_LOOKUP_TIMEOUT_SECS 60
#define AUTH_WORKER_MAX_IDLE_SECS (60*30)

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
	struct timeout *to;

	unsigned int id_counter;
        ARRAY_DEFINE(requests, struct auth_worker_request);

	unsigned int request_count;
	unsigned int requests_left;
};

static ARRAY_DEFINE(connections, struct auth_worker_connection *) = ARRAY_INIT;
static unsigned int idle_count;
static unsigned int auth_workers_max;
static unsigned int auth_workers_max_request_count;

static char *worker_socket_path;

static void worker_input(struct auth_worker_connection *conn);
static void auth_worker_destroy(struct auth_worker_connection *conn,
				const char *reason);

static void auth_worker_idle_timeout(struct auth_worker_connection *conn)
{
	i_assert(array_count(&conn->requests) == 0);

	if (idle_count > 1)
		auth_worker_destroy(conn, NULL);
	else
		timeout_reset(conn->to);
}

static struct auth_worker_connection *auth_worker_create(void)
{
	struct auth_worker_connection *conn;
	int fd, try;

	if (array_count(&connections) >= auth_workers_max)
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
	conn->input = i_stream_create_fd(fd, AUTH_WORKER_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_READ, worker_input, conn);
	i_array_init(&conn->requests, 16);
	conn->requests_left = auth_workers_max_request_count;
	conn->to = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
			       auth_worker_idle_timeout, conn);

	idle_count++;

	array_append(&connections, &conn, 1);
	return conn;
}

static void auth_worker_destroy(struct auth_worker_connection *conn,
				const char *reason)
{
	struct auth_worker_connection **connp;
	struct auth_worker_request *requests;
	unsigned int i, count;
	const char *reply;

	connp = array_get_modifiable(&connections, &count);
	for (i = 0; i < count; i++) {
		if (connp[i] == conn) {
			array_delete(&connections, i, 1);
			break;
		}
	}

	if (conn->request_count == 0)
		idle_count--;

	/* abort all pending requests */
	reply = t_strdup_printf("FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE);

	requests = array_get_modifiable(&conn->requests, &count);
	for (i = 0; i < count; i++) {
		if (requests[i].id != 0) {
			auth_request_log_error(requests[i].auth_request,
					       "worker-server",
					       "Aborted: %s", reason);
			T_BEGIN {
				requests[i].callback(requests[i].auth_request,
						     reply);
			} T_END;
			auth_request_unref(&requests[i].auth_request);
		}
	}


	array_free(&conn->requests);
	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	timeout_remove(&conn->to);

	if (close(conn->fd) < 0)
		i_error("close(auth worker) failed: %m");
	i_free(conn);
}

static struct auth_worker_request *
auth_worker_request_lookup(struct auth_worker_connection *conn,
			   unsigned int id)
{
	struct auth_worker_request *requests;
	unsigned int i, count;

	requests = array_get_modifiable(&conn->requests, &count);
	for (i = 0; i < count; i++) {
		if (requests[i].id == id)
			return &requests[i];
	}
	return NULL;
}

static struct auth_worker_connection *auth_worker_find_free(void)
{
	struct auth_worker_connection **conn, *best;
	unsigned int i, count;
	size_t outbuf_size, best_size;

	conn = array_get_modifiable(&connections, &count);
	if (idle_count > 0) {
		/* there exists at least one idle connection, use it */
		for (i = 0; i < count; i++) {
			if (conn[i]->request_count == 0)
				return conn[i];
		}
		i_unreached();
	}

	/* first the connection with least data in output buffer */
	best = NULL;
	best_size = (size_t)-1;
	for (i = 0; i < count; i++) {
		outbuf_size = o_stream_get_buffer_used_size(conn[i]->output);
		if (outbuf_size < best_size && conn[i]->requests_left > 0) {
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
	if (conn->request_count > 0)
		timeout_reset(conn->to);
	else {
		timeout_remove(&conn->to);
		conn->to = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
				       auth_worker_idle_timeout, conn);
		idle_count++;
	}
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
		auth_worker_destroy(conn, "Worker process died unexpectedly");
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth worker sent us more than %d bytes",
			(int)AUTH_WORKER_MAX_LINE_LENGTH);
		auth_worker_destroy(conn, "Worker is buggy");
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		id_str = line;
		line = strchr(line, '\t');
		if (line == NULL)
			continue;

		T_BEGIN {
			id = (unsigned int)strtoul(t_strcut(id_str, '\t'),
						   NULL, 10);
			request = auth_worker_request_lookup(conn, id);
		} T_END;

		if (request != NULL)
			auth_worker_handle_request(conn, request, line + 1);
	}

	if (conn->requests_left == 0 && array_count(&conn->requests) == 0) {
		auth_worker_destroy(conn, "Max requests limit");
		if (idle_count == 0)
			auth_worker_create();
	}
}

static struct auth_worker_request *
auth_worker_request_get(struct auth_worker_connection *conn)
{
        struct auth_worker_request *request;

	request = auth_worker_request_lookup(conn, 0);
	return request != NULL ? request : array_append_space(&conn->requests);
}

static void auth_worker_call_timeout(struct auth_worker_connection *conn)
{
	i_assert(array_count(&conn->requests) > 0);

	auth_worker_destroy(conn, "Lookup timed out");
}

void auth_worker_call(struct auth_request *auth_request,
		      struct auth_stream_reply *data,
		      auth_worker_callback_t *callback)
{
	struct auth_worker_connection *conn;
	struct auth_worker_request *request;
	const char *reply, *data_str;
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

	i_assert(conn->requests_left > 0);

	data_str = auth_stream_reply_export(data);
	iov[0].iov_base = t_strdup_printf("%d\t", ++conn->id_counter);
	iov[0].iov_len = strlen(iov[0].iov_base);
	iov[1].iov_base = data_str;
	iov[1].iov_len = strlen(data_str);
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

	if (conn->request_count == 0) {
		timeout_remove(&conn->to);
		conn->to = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
				       auth_worker_call_timeout, conn);
		idle_count--;
	}
	conn->request_count++;
	conn->requests_left--;
}

void auth_worker_server_init(void)
{
	const char *env;

	if (array_is_created(&connections)) {
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

	env = getenv("AUTH_WORKER_MAX_REQUEST_COUNT");
	if (env == NULL)
		i_fatal("AUTH_WORKER_MAX_REQUEST_COUNT environment not set");
	auth_workers_max_request_count = atoi(env);
	if (auth_workers_max_request_count == 0)
		auth_workers_max_request_count = (unsigned int)-1;

	i_array_init(&connections, 16);
	auth_worker_create();
}

void auth_worker_server_deinit(void)
{
	struct auth_worker_connection **connp;

	if (!array_is_created(&connections))
		return;

	while (array_count(&connections) > 0) {
		connp = array_idx_modifiable(&connections, 0);
		auth_worker_destroy(*connp, "Shutting down");
	}
	array_free(&connections);

	i_free(worker_socket_path);
}
