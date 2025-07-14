/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "strescape.h"
#include "master-service.h"
#include "replication-common.h"
#include "replicator-connection.h"
#include "notify-connection.h"
#include "aggregator-settings.h"

#define MAX_INBUF_SIZE 8192

#define CONNECTION_IS_FIFO(conn) \
	((conn)->output == NULL)

struct notify_connection {
	struct notify_connection *prev, *next;
	struct event *event;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
};

static struct notify_connection *conns = NULL;

static void notify_connection_unref(struct notify_connection *conn);
static void notify_connection_destroy(struct notify_connection *conn);

static bool notify_input_error(struct notify_connection *conn)
{
	if (CONNECTION_IS_FIFO(conn))
		return TRUE;
	notify_connection_destroy(conn);
	return FALSE;
}

void notify_connection_sync_callback(bool success, void *context)
{
	struct notify_connection *conn = context;

	e_debug(conn->event, "Sending %s result",
		success ? "success" : "failure");
	o_stream_nsend_str(conn->output, success ? "+\n" : "-\n");
	notify_connection_unref(conn);
}

static int
notify_input_line(struct notify_connection *conn, const char *line,
		  const char **error_r)
{
	const char *const *args;
	enum replication_priority priority;

	/* <username> \t <priority> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) < 2) {
		*error_r = "Client sent invalid input";
		return -1;
	}
	if (replication_priority_parse(args[1], &priority) < 0) {
		*error_r = t_strdup_printf(
			"Client sent invalid priority: %s", args[1]);
		return -1;
	}

	e_debug(conn->event, "Received priority %s request for %s",
		args[1], args[0]);

	if (priority != REPLICATION_PRIORITY_SYNC)
		replicator_connection_notify(replicator, args[0], priority);
	else {
		conn->refcount++;
		replicator_connection_notify_sync(replicator, args[0], conn);
	}
	return 0;
}

static void notify_input(struct notify_connection *conn)
{
	const char *line;
	int ret;
	const char *error;

	switch (i_stream_read(conn->input)) {
	case -2:
		/* buffer full */
		e_error(conn->event, "Client sent too long line");
		(void)notify_input_error(conn);
		return;
	case -1:
		/* disconnected */
		notify_connection_destroy(conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = notify_input_line(conn, line, &error);
			if (ret < 0)
				e_error(conn->event, "%s", error);
		} T_END;
		if (ret < 0) {
			if (!notify_input_error(conn))
				return;
		}
	}
}

void notify_connection_create(int fd, bool fifo, const char *name)
{
	struct notify_connection *conn;

	conn = i_new(struct notify_connection, 1);
	conn->refcount = 1;
	conn->fd = fd;
	conn->io = io_add(fd, IO_READ, notify_input, conn);
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE);
	i_stream_set_name(conn->input, name);
	conn->event = event_create(NULL);
	event_set_append_log_prefix(conn->event,
		t_strdup_printf("notify(%s): ", name));
	if (!fifo) {
		conn->output = o_stream_create_fd(fd, SIZE_MAX);
		o_stream_set_no_error_handling(conn->output, TRUE);
	}

	DLLIST_PREPEND(&conns, conn);
}

static void notify_connection_unref(struct notify_connection *conn)
{
	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;

	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	event_unref(&conn->event);
	i_free(conn);
}

static void notify_connection_destroy(struct notify_connection *conn)
{
	i_assert(conn->fd != -1);

	e_debug(conn->event, "Disconnected");

	if (!CONNECTION_IS_FIFO(conn))
		master_service_client_connection_destroyed(master_service);

	DLLIST_REMOVE(&conns, conn);

	io_remove(&conn->io);
	i_stream_close(conn->input);
	o_stream_close(conn->output);
	net_disconnect(conn->fd);
	conn->fd = -1;

	notify_connection_unref(conn);
}

void notify_connections_destroy_all(void)
{
	while (conns != NULL)
		notify_connection_destroy(conns);
}
