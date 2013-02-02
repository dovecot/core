/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "master-service.h"
#include "replicator-queue.h"
#include "notify-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE (1024*64)
#define NOTIFY_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define NOTIFY_CLIENT_PROTOCOL_MINOR_VERSION 0

struct notify_connection {
	struct notify_connection *prev, *next;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct replicator_queue *queue;

	unsigned int version_received:1;
	unsigned int destroyed:1;
};

struct notify_sync_request {
	struct notify_connection *conn;
	unsigned int id;
};

static struct notify_connection *connections;

static void notify_connection_destroy(struct notify_connection *conn);

static void notify_sync_callback(bool success, void *context)
{
	struct notify_sync_request *request = context;

	o_stream_nsend_str(request->conn->output, t_strdup_printf(
		"%c\t%u\n", success ? '+' : '-', request->id));

	notify_connection_unref(&request->conn);
	i_free(request);
}

static int
notify_connection_input_line(struct notify_connection *conn, const char *line)
{
	struct notify_sync_request *request;
	const char *const *args;
	enum replication_priority priority;
	unsigned int id;

	/* U \t <username> \t <priority> [\t <sync id>] */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) < 2) {
		i_error("notify client sent invalid input: %s", line);
		return -1;
	}
	if (strcmp(args[0], "U") != 0) {
		i_error("notify client sent unknown command: %s", args[0]);
		return -1;
	}
	if (replication_priority_parse(args[2], &priority) < 0) {
		i_error("notify client sent invalid priority: %s", args[2]);
		return -1;
	}
	if (priority != REPLICATION_PRIORITY_SYNC)
		(void)replicator_queue_add(conn->queue, args[1], priority);
	else if (args[3] == NULL || str_to_uint(args[3], &id) < 0) {
		i_error("notify client sent invalid sync id: %s", line);
		return -1;
	} else {
		request = i_new(struct notify_sync_request, 1);
		request->conn = conn;
		request->id = id;
		notify_connection_ref(conn);
		replicator_queue_add_sync(conn->queue, args[1],
					  notify_sync_callback, request);
	}
	return 0;
}

static void notify_connection_input(struct notify_connection *conn)
{
	const char *line;
	int ret;

	switch (i_stream_read(conn->input)) {
	case -2:
		i_error("BUG: Client connection sent too much data");
		notify_connection_destroy(conn);
		return;
	case -1:
		notify_connection_destroy(conn);
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, "replicator-notify",
				NOTIFY_CLIENT_PROTOCOL_MAJOR_VERSION)) {
			i_error("Notify client not compatible with this server "
				"(mixed old and new binaries?)");
			notify_connection_destroy(conn);
			return;
		}
		conn->version_received = TRUE;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = notify_connection_input_line(conn, line);
		} T_END;
		if (ret < 0) {
			notify_connection_destroy(conn);
			break;
		}
	}
}

struct notify_connection *
notify_connection_create(int fd, struct replicator_queue *queue)
{
	struct notify_connection *conn;

	i_assert(fd >= 0);

	conn = i_new(struct notify_connection, 1);
	conn->refcount = 1;
	conn->queue = queue;
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);
	conn->io = io_add(fd, IO_READ, notify_connection_input, conn);
	conn->queue = queue;

	DLLIST_PREPEND(&connections, conn);
	return conn;
}

static void notify_connection_destroy(struct notify_connection *conn)
{
	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	DLLIST_REMOVE(&connections, conn);

	io_remove(&conn->io);
	i_stream_close(conn->input);
	o_stream_close(conn->output);
	if (close(conn->fd) < 0)
		i_error("close(notify connection) failed: %m");
	conn->fd = -1;

	notify_connection_unref(&conn);
	master_service_client_connection_destroyed(master_service);
}

void notify_connection_ref(struct notify_connection *conn)
{
	i_assert(conn->refcount > 0);

	conn->refcount++;
}

void notify_connection_unref(struct notify_connection **_conn)
{
	struct notify_connection *conn = *_conn;

	i_assert(conn->refcount > 0);

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	notify_connection_destroy(conn);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	i_free(conn);
}

void notify_connections_destroy_all(void)
{
	while (connections != NULL)
		notify_connection_destroy(connections);
}
