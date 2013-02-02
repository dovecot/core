/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "indexer-queue.h"
#include "worker-connection.h"

#include <unistd.h>

#define INDEXER_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_PROTOCOL_MINOR_VERSION 0

#define INDEXER_MASTER_HANDSHAKE "VERSION\tindexer-master-worker\t1\t0\n"
#define INDEXER_WORKER_NAME "indexer-worker-master"

struct worker_connection {
	int refcount;

	char *socket_path;
	indexer_status_callback_t *callback;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	char *request_username;
	ARRAY(void *) request_contexts;
	struct aqueue *request_queue;

	unsigned int process_limit;
	unsigned int version_received:1;
};

struct worker_connection *
worker_connection_create(const char *socket_path,
			 indexer_status_callback_t *callback)
{
	struct worker_connection *conn;

	conn = i_new(struct worker_connection, 1);
	conn->refcount = 1;
	conn->socket_path = i_strdup(socket_path);
	conn->callback = callback;
	conn->fd = -1;
	i_array_init(&conn->request_contexts, 32);
	conn->request_queue = aqueue_init(&conn->request_contexts.arr);
	return conn;
}

static void worker_connection_unref(struct worker_connection *conn)
{
	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;

	aqueue_deinit(&conn->request_queue);
	array_free(&conn->request_contexts);
	i_free(conn->socket_path);
	i_free(conn);
}

static void worker_connection_disconnect(struct worker_connection *conn)
{
	unsigned int i, count = aqueue_count(conn->request_queue);

	if (conn->fd != -1) {
		io_remove(&conn->io);
		i_stream_destroy(&conn->input);
		o_stream_destroy(&conn->output);

		if (close(conn->fd) < 0)
			i_error("close(%s) failed: %m", conn->socket_path);
		conn->fd = -1;
	}

	/* cancel any pending requests */
	if (count > 0) {
		i_error("Indexer worker disconnected, "
			"discarding %u requests for %s",
			count, conn->request_username);
	}

	/* conn->callback() can try to destroy us */
	conn->refcount++;
	for (i = 0; i < count; i++) {
		void *const *contextp =
			array_idx(&conn->request_contexts,
				  aqueue_idx(conn->request_queue, 0));
		void *context = *contextp;

		aqueue_delete_tail(conn->request_queue);
		conn->callback(-1, context);
	}
	i_free_and_null(conn->request_username);
	worker_connection_unref(conn);
}

void worker_connection_destroy(struct worker_connection **_conn)
{
	struct worker_connection *conn = *_conn;

	*_conn = NULL;

	worker_connection_disconnect(conn);
	worker_connection_unref(conn);
}

static int
worker_connection_input_line(struct worker_connection *conn, const char *line)
{
	void *const *contextp, *context;
	int percentage;

	if (aqueue_count(conn->request_queue) == 0) {
		i_error("Input from worker without pending requests: %s", line);
		return -1;
	}

	if (str_to_int(line, &percentage) < 0 ||
	    percentage < -1 || percentage > 100) {
		i_error("Invalid input from worker: %s", line);
		return -1;
	}

	contextp = array_idx(&conn->request_contexts,
			     aqueue_idx(conn->request_queue, 0));
	context = *contextp;
	if (percentage < 0 || percentage == 100) {
		/* the request is finished */
		aqueue_delete_tail(conn->request_queue);
		if (aqueue_count(conn->request_queue) == 0)
			i_free_and_null(conn->request_username);
	}

	conn->callback(percentage, context);
	return 0;
}

static void worker_connection_input(struct worker_connection *conn)
{
	const char *line;

	if (i_stream_read(conn->input) < 0) {
		worker_connection_disconnect(conn);
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, INDEXER_WORKER_NAME,
				INDEXER_PROTOCOL_MAJOR_VERSION)) {
			i_error("Indexer worker not compatible with this master "
				"(mixed old and new binaries?)");
			worker_connection_disconnect(conn);
			return;
		}
		conn->version_received = TRUE;
	}
	if (conn->process_limit == 0) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;
		if (str_to_uint(line, &conn->process_limit) < 0 ||
		    conn->process_limit == 0) {
			i_error("Indexer worker sent invalid handshake: %s",
				line);
			worker_connection_disconnect(conn);
			return;
		}
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		if (worker_connection_input_line(conn, line) < 0) {
			worker_connection_disconnect(conn);
			break;
		}
	}
}

int worker_connection_connect(struct worker_connection *conn)
{
	i_assert(conn->fd == -1);

	conn->fd = net_connect_unix(conn->socket_path);
	if (conn->fd == -1) {
		i_error("connect(%s) failed: %m", conn->socket_path);
		return -1;
	}
	conn->io = io_add(conn->fd, IO_READ, worker_connection_input, conn);
	conn->input = i_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_nsend_str(conn->output, INDEXER_MASTER_HANDSHAKE);
	return 0;
}

bool worker_connection_is_connected(struct worker_connection *conn)
{
	return conn->fd != -1;
}

bool worker_connection_get_process_limit(struct worker_connection *conn,
					 unsigned int *limit_r)
{
	if (conn->process_limit == 0)
		return FALSE;

	*limit_r = conn->process_limit;
	return TRUE;
}

void worker_connection_request(struct worker_connection *conn,
			       const struct indexer_request *request,
			       void *context)
{
	i_assert(worker_connection_is_connected(conn));
	i_assert(context != NULL);
	i_assert(request->index || request->optimize);

	if (conn->request_username == NULL)
		conn->request_username = i_strdup(request->username);
	else {
		i_assert(strcmp(conn->request_username,
				request->username) == 0);
	}

	aqueue_append(conn->request_queue, &context);

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append_tabescaped(str, request->username);
		str_append_c(str, '\t');
		str_append_tabescaped(str, request->mailbox);
		str_printfa(str, "\t%u\t", request->max_recent_msgs);
		if (request->index)
			str_append_c(str, 'i');
		if (request->optimize)
			str_append_c(str, 'o');
		str_append_c(str, '\n');
		o_stream_nsend(conn->output, str_data(str), str_len(str));
	} T_END;
}

bool worker_connection_is_busy(struct worker_connection *conn)
{
	return aqueue_count(conn->request_queue) > 0;
}

const char *worker_connection_get_username(struct worker_connection *conn)
{
	return conn->request_username;
}
