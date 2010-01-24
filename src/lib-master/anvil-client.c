/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "aqueue.h"
#include "anvil-client.h"

struct anvil_query {
	anvil_callback_t *callback;
	void *context;
};

struct anvil_client {
	char *path;
	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	ARRAY_DEFINE(queries_arr, struct anvil_query);
	struct aqueue *queries;

	bool (*reconnect_callback)(void);
	enum anvil_client_flags flags;
};

#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"
#define ANVIL_INBUF_SIZE 1024

static void anvil_client_disconnect(struct anvil_client *client);

struct anvil_client *
anvil_client_init(const char *path, bool (*reconnect_callback)(void),
		  enum anvil_client_flags flags)
{
	struct anvil_client *client;

	client = i_new(struct anvil_client, 1);
	client->path = i_strdup(path);
	client->reconnect_callback = reconnect_callback;
	client->flags = flags;
	client->fd = -1;
	i_array_init(&client->queries_arr, 32);
	client->queries = aqueue_init(&client->queries_arr.arr);
	return client;
}

void anvil_client_deinit(struct anvil_client **_client)
{
	struct anvil_client *client = *_client;

	*_client = NULL;

	anvil_client_disconnect(client);
	array_free(&client->queries_arr);
	aqueue_deinit(&client->queries);
	i_free(client->path);
	i_free(client);
}

static void anvil_reconnect(struct anvil_client *client)
{
	anvil_client_disconnect(client);
	if (client->reconnect_callback != NULL) {
		if (!client->reconnect_callback()) {
			/* no reconnection */
			return;
		}
	}
	(void)anvil_client_connect(client, FALSE);
}

static void anvil_input(struct anvil_client *client)
{
	const struct anvil_query *queries, *query;
	const char *line;
	unsigned int count;

	queries = array_get(&client->queries_arr, &count);
	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (aqueue_count(client->queries) == 0) {
			i_error("anvil: Unexpected input: %s", line);
			continue;
		}

		query = &queries[aqueue_idx(client->queries, 0)];
		query->callback(line, query->context);
		aqueue_delete_tail(client->queries);
	}
	if (client->input->stream_errno != 0) {
		i_error("read(%s) failed: %m", client->path);
		anvil_reconnect(client);
	} else if (client->input->eof) {
		i_error("read(%s) failed: EOF", client->path);
		anvil_reconnect(client);
	}
}

int anvil_client_connect(struct anvil_client *client, bool retry)
{
	int fd;

	i_assert(client->fd == -1);

	fd = retry ? net_connect_unix_with_retries(client->path, 5000) :
		net_connect_unix(client->path);
	if (fd == -1) {
		if (errno != ENOENT ||
		    (client->flags & ANVIL_CLIENT_FLAG_HIDE_ENOENT) == 0) {
			i_error("net_connect_unix(%s) failed: %m",
				client->path);
		}
		return -1;
	}

	client->fd = fd;
	client->input = i_stream_create_fd(fd, ANVIL_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	client->io = io_add(fd, IO_READ, anvil_input, client);
	o_stream_send_str(client->output, ANVIL_HANDSHAKE);
	return 0;
}

static void anvil_client_cancel_queries(struct anvil_client *client)
{
	const struct anvil_query *queries, *query;
	unsigned int count;

	queries = array_get(&client->queries_arr, &count);
	while (aqueue_count(client->queries) > 0) {
		query = &queries[aqueue_idx(client->queries, 0)];
		query->callback(NULL, query->context);
		aqueue_delete_tail(client->queries);
	}
}

static void anvil_client_disconnect(struct anvil_client *client)
{
	if (client->fd == -1)
		return;

	anvil_client_cancel_queries(client);
	io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	net_disconnect(client->fd);
	client->fd = -1;
}

static int anvil_client_send(struct anvil_client *client, const char *cmd)
{
	struct const_iovec iov[2];

	if (client->fd == -1) {
		if (anvil_client_connect(client, FALSE) < 0)
			return -1;
	}

	iov[0].iov_base = cmd;
	iov[0].iov_len = strlen(cmd);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	o_stream_sendv(client->output, iov, 2);
	return 0;
}

void anvil_client_query(struct anvil_client *client, const char *query,
			anvil_callback_t *callback, void *context)
{
	struct anvil_query anvil_query;

	if (anvil_client_send(client, query) < 0) {
		callback(NULL, context);
		return;
	}

	anvil_query.callback = callback;
	anvil_query.context = context;
	aqueue_append(client->queries, &anvil_query);
}

void anvil_client_cmd(struct anvil_client *client, const char *cmd)
{
	(void)anvil_client_send(client, cmd);
}
