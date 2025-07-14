/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "buffer.h"
#include "hash.h"
#include "llist.h"
#include "strescape.h"
#include "replicator-connection.h"
#include "aggregator-settings.h"

#define MAX_INBUF_SIZE 1024
#define REPLICATOR_RECONNECT_MSECS 5000
#define REPLICATOR_MEMBUF_MAX_SIZE 1024*1024
#define REPLICATOR_HANDSHAKE "VERSION\treplicator-notify\t1\t0\n"

struct replicator_connection {
	char *path;
	struct event *event;
	struct ip_addr *ips;
	unsigned int ips_count, ip_idx;
	in_port_t port;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	buffer_t *queue[REPLICATION_PRIORITY_SYNC + 1];

	HASH_TABLE(void *, void *) requests;
	unsigned int request_id_counter;
	replicator_sync_callback_t *callback;
};

static void replicator_connection_disconnect(struct replicator_connection *conn);

static int
replicator_input_line(struct replicator_connection *conn, const char *line)
{
	void *context;
	unsigned int id;

	/* <+|-> \t <id> */
	if ((line[0] != '+' && line[0] != '-') || line[1] != '\t' ||
	    str_to_uint(line+2, &id) < 0 || id == 0) {
		e_error(conn->event, "Replicator sent invalid input: %s", line);
		return -1;
	}

	context = hash_table_lookup(conn->requests, POINTER_CAST(id));
	if (context == NULL) {
		e_error(conn->event, "Replicator sent invalid ID: %u", id);
		return -1;
	}

	e_debug(conn->event, "Request id %u has %s",
		id, line[0] == '+' ? "succeeded" : "failed");
	hash_table_remove(conn->requests, POINTER_CAST(id));
	conn->callback(line[0] == '+', context);
	return 0;
}

static void replicator_input(struct replicator_connection *conn)
{
	const char *line;

	switch (i_stream_read(conn->input)) {
	case -2:
		/* buffer full */
		e_error(conn->event, "Replicator sent too long line");
		replicator_connection_disconnect(conn);
		return;
	case -1:
		/* disconnected */
		replicator_connection_disconnect(conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL)
		(void)replicator_input_line(conn, line);
}

static bool
replicator_send_buf(struct replicator_connection *conn, buffer_t *buf)
{
	const unsigned char *data = buf->data;
	size_t len = IO_BLOCK_SIZE;

	/* try to send about IO_BLOCK_SIZE amount of data,
	   but only full lines */
	if (len >= buf->used)
		len = buf->used - 1;
	for (;; len++) {
		i_assert(len < buf->used); /* there is always LF */
		if (data[len] == '\n') {
			len++;
			break;
		}
	}

	if (o_stream_send(conn->output, data, len) < 0) {
		replicator_connection_disconnect(conn);
		return FALSE;
	}
	buffer_delete(buf, 0, len);
	return TRUE;
}

static int replicator_output(struct replicator_connection *conn)
{
	enum replication_priority p;

	if (o_stream_flush(conn->output) < 0) {
		replicator_connection_disconnect(conn);
		return 1;
	}

	for (p = REPLICATION_PRIORITY_SYNC;;) {
		if (o_stream_get_buffer_used_size(conn->output) > 0) {
			o_stream_set_flush_pending(conn->output, TRUE);
			break;
		}
		/* output buffer is empty, send more data */
		if (conn->queue[p]->used > 0) {
			if (!replicator_send_buf(conn, conn->queue[p]))
				break;
		} else {
			if (p == REPLICATION_PRIORITY_LOW)
				break;
			p--;
		}
	}
	return 1;
}

static void replicator_connection_connect(struct replicator_connection *conn)
{
	unsigned int n;
	int fd = -1;

	if (conn->fd != -1)
		return;

	if (conn->port == 0) {
		event_set_append_log_prefix(conn->event,
					    t_strdup_printf("(unix:%s): ", conn->path));
		e_debug(conn->event, "Connecting to replicator");
		fd = net_connect_unix(conn->path);
		if (fd == -1)
			e_error(conn->event, "net_connect_unix(%s) failed: %m",
				conn->path);
	} else {
		for (n = 0; n < conn->ips_count; n++) {
			unsigned int idx = conn->ip_idx;

			conn->ip_idx = (conn->ip_idx + 1) % conn->ips_count;
			event_set_append_log_prefix(conn->event, t_strdup_printf(
				"(%s): ", net_ipport2str(&conn->ips[idx], conn->port)));
			e_debug(conn->event, "Connecting to replicator");
			fd = net_connect_ip(&conn->ips[idx], conn->port, NULL);
			if (fd != -1)
				break;
			e_error(conn->event, "connect(%s, %u) failed: %m",
				net_ip2addr(&conn->ips[idx]), conn->port);
		}
	}

	if (fd == -1) {
		event_set_append_log_prefix(conn->event, "");
		if (conn->to == NULL) {
			e_debug(conn->event, "Reconnecting in %u msecs", REPLICATOR_RECONNECT_MSECS);
			conn->to = timeout_add(REPLICATOR_RECONNECT_MSECS,
					       replicator_connection_connect,
					       conn);
		}
		return;
	}

	timeout_remove(&conn->to);
	conn->fd = fd;
	conn->io = io_add(fd, IO_READ, replicator_input, conn);
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE);
	conn->output = o_stream_create_fd(fd, SIZE_MAX);
	e_debug(conn->event, "Sending handshake");
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_nsend_str(conn->output, REPLICATOR_HANDSHAKE);
	o_stream_set_flush_callback(conn->output, replicator_output, conn);
}

static void replicator_abort_all_requests(struct replicator_connection *conn)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	e_debug(conn->event, "Aborting all requests");
	iter = hash_table_iterate_init(conn->requests);
	while (hash_table_iterate(iter, conn->requests, &key, &value))
		conn->callback(FALSE, value);
	hash_table_iterate_deinit(&iter);
	hash_table_clear(conn->requests, TRUE);
}

static void replicator_connection_disconnect(struct replicator_connection *conn)
{
	if (conn->fd == -1)
		return;

	e_debug(conn->event, "Disconnecting");
	replicator_abort_all_requests(conn);
	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	net_disconnect(conn->fd);
	event_set_append_log_prefix(conn->event, "");
	conn->fd = -1;
}

static struct replicator_connection *replicator_connection_create(void)
{
	struct replicator_connection *conn;
	unsigned int i;

	conn = i_new(struct replicator_connection, 1);
	conn->fd = -1;
	conn->event = event_create(NULL);
	hash_table_create_direct(&conn->requests, default_pool, 0);
	for (i = REPLICATION_PRIORITY_LOW; i <= REPLICATION_PRIORITY_SYNC; i++)
		conn->queue[i] = buffer_create_dynamic(default_pool, 1024);
	return conn;
}

struct replicator_connection *
replicator_connection_create_unix(const char *path,
				  replicator_sync_callback_t *callback)
{
	struct replicator_connection *conn;

	conn = replicator_connection_create();
	conn->callback = callback;
	conn->path = i_strdup(path);
	return conn;
}

struct replicator_connection *
replicator_connection_create_inet(const struct ip_addr *ips,
				  unsigned int ips_count, in_port_t port,
				  replicator_sync_callback_t *callback)
{
	struct replicator_connection *conn;

	i_assert(ips_count > 0);

	conn = replicator_connection_create();
	conn->callback = callback;
	conn->ips = i_new(struct ip_addr, ips_count);
	memcpy(conn->ips, ips, sizeof(*ips) * ips_count);
	conn->ips_count = ips_count;
	conn->port = port;
	return conn;
}

void replicator_connection_destroy(struct replicator_connection **_conn)
{
	struct replicator_connection *conn = *_conn;
	unsigned int i;

	*_conn = NULL;
	replicator_connection_disconnect(conn);

	for (i = REPLICATION_PRIORITY_LOW; i <= REPLICATION_PRIORITY_SYNC; i++)
		buffer_free(&conn->queue[i]);

	timeout_remove(&conn->to);
	hash_table_destroy(&conn->requests);
	event_unref(&conn->event);
	i_free(conn->ips);
	i_free(conn->path);
	i_free(conn);
}

static void
replicator_send(struct replicator_connection *conn,
		enum replication_priority priority, const char *data)
{
	size_t data_len = strlen(data);

	if (conn->fd != -1 &&
	    o_stream_get_buffer_used_size(conn->output) == 0) {
		/* we can send data immediately */
		o_stream_nsend(conn->output, data, data_len);
	} else if (conn->queue[priority]->used + data_len >=
		   	REPLICATOR_MEMBUF_MAX_SIZE) {
		/* FIXME: compress duplicates, start writing to file */
	} else {
		/* queue internally to separate queues */
		buffer_append(conn->queue[priority], data, data_len);
		if (conn->output != NULL)
			o_stream_set_flush_pending(conn->output, TRUE);
	}
}

void replicator_connection_notify(struct replicator_connection *conn,
				  const char *username,
				  enum replication_priority priority)
{
	const char *priority_str = "";

	replicator_connection_connect(conn);

	switch (priority) {
	case REPLICATION_PRIORITY_NONE:
	case REPLICATION_PRIORITY_SYNC:
		i_unreached();
	case REPLICATION_PRIORITY_LOW:
		priority_str = "low";
		break;
	case REPLICATION_PRIORITY_HIGH:
		priority_str = "high";
		break;
	}

	T_BEGIN {
		e_debug(conn->event, "Requesting replication of %s priority for user %s",
			priority_str, username);
		replicator_send(conn, priority, t_strdup_printf(
			"U\t%s\t%s\n", str_tabescape(username), priority_str));
	} T_END;
}

void replicator_connection_notify_sync(struct replicator_connection *conn,
				       const char *username, void *context)
{
	unsigned int id;

	replicator_connection_connect(conn);

	id = ++conn->request_id_counter;
	if (id == 0) id++;
	hash_table_insert(conn->requests, POINTER_CAST(id), context);

	T_BEGIN {
		e_debug(conn->event, "Requesting synchronization with id %u for user %s",
			id, username);
		replicator_send(conn, REPLICATION_PRIORITY_SYNC, t_strdup_printf(
			"U\t%s\tsync\t%u\n", str_tabescape(username), id));
	} T_END;
}
