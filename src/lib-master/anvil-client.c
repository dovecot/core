/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
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
	struct timeout *to_query;

	struct timeout *to_reconnect;
	time_t last_reconnect;

	ARRAY(struct anvil_query *) queries_arr;
	struct aqueue *queries;

	bool (*reconnect_callback)(void);
	enum anvil_client_flags flags;
};

#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"
#define ANVIL_INBUF_SIZE 1024
#define ANVIL_RECONNECT_MIN_SECS 5
#define ANVIL_QUERY_TIMEOUT_MSECS (1000*5)

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
	i_assert(client->to_reconnect == NULL);
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

	if (ioloop_time - client->last_reconnect < ANVIL_RECONNECT_MIN_SECS) {
		if (client->to_reconnect == NULL) {
			client->to_reconnect =
				timeout_add(ANVIL_RECONNECT_MIN_SECS*1000,
					    anvil_reconnect, client);
		}
	} else {
		client->last_reconnect = ioloop_time;
		(void)anvil_client_connect(client, FALSE);
	}
}

static void anvil_input(struct anvil_client *client)
{
	struct anvil_query *const *queries;
	struct anvil_query *query;
	const char *line;
	unsigned int count;

	queries = array_get(&client->queries_arr, &count);
	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (aqueue_count(client->queries) == 0) {
			i_error("anvil: Unexpected input: %s", line);
			continue;
		}

		query = queries[aqueue_idx(client->queries, 0)];
		if (query->callback != NULL) T_BEGIN {
			query->callback(line, query->context);
		} T_END;
		i_free(query);
		aqueue_delete_tail(client->queries);
	}
	if (client->input->stream_errno != 0) {
		i_error("read(%s) failed: %s", client->path,
			i_stream_get_error(client->input));
		anvil_reconnect(client);
	} else if (client->input->eof) {
		i_error("read(%s) failed: EOF", client->path);
		anvil_reconnect(client);
	} else if (client->to_query != NULL) {
		if (aqueue_count(client->queries) == 0)
			timeout_remove(&client->to_query);
		else
			timeout_reset(client->to_query);
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

	timeout_remove(&client->to_reconnect);

	client->fd = fd;
	client->input = i_stream_create_fd(fd, ANVIL_INBUF_SIZE);
	client->output = o_stream_create_fd(fd, (size_t)-1);
	client->io = io_add(fd, IO_READ, anvil_input, client);
	if (o_stream_send_str(client->output, ANVIL_HANDSHAKE) < 0) {
		i_error("write(%s) failed: %s", client->path,
			o_stream_get_error(client->output));
		anvil_reconnect(client);
		return -1;
	}
	return 0;
}

static void anvil_client_cancel_queries(struct anvil_client *client)
{
	struct anvil_query *const *queries, *query;
	unsigned int count;

	queries = array_get(&client->queries_arr, &count);
	while (aqueue_count(client->queries) > 0) {
		query = queries[aqueue_idx(client->queries, 0)];
		if (query->callback != NULL)
			query->callback(NULL, query->context);
		i_free(query);
		aqueue_delete_tail(client->queries);
	}
	timeout_remove(&client->to_query);
}

static void anvil_client_disconnect(struct anvil_client *client)
{
	anvil_client_cancel_queries(client);
	if (client->fd != -1) {
		io_remove(&client->io);
		i_stream_destroy(&client->input);
		o_stream_destroy(&client->output);
		net_disconnect(client->fd);
		client->fd = -1;
	}
	timeout_remove(&client->to_reconnect);
}

static void anvil_client_timeout(struct anvil_client *client)
{
	i_assert(aqueue_count(client->queries) > 0);

	i_error("%s: Anvil queries timed out after %u secs - aborting queries",
		client->path, ANVIL_QUERY_TIMEOUT_MSECS/1000);
	/* perhaps reconnect helps */
	anvil_reconnect(client);
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
	if (o_stream_sendv(client->output, iov, 2) < 0) {
		i_error("write(%s) failed: %s", client->path,
			o_stream_get_error(client->output));
		anvil_reconnect(client);
		return -1;
	}
	return 0;
}

struct anvil_query *
anvil_client_query(struct anvil_client *client, const char *query,
		   anvil_callback_t *callback, void *context)
{
	struct anvil_query *anvil_query;

	anvil_query = i_new(struct anvil_query, 1);
	anvil_query->callback = callback;
	anvil_query->context = context;
	aqueue_append(client->queries, &anvil_query);
	if (anvil_client_send(client, query) < 0) {
		/* connection failure. add a delayed failure callback.
		   the caller may not expect the callback to be called
		   immediately. */
		timeout_remove(&client->to_query);
		client->to_query =
			timeout_add_short(0, anvil_client_cancel_queries, client);
	} else if (client->to_query == NULL) {
		client->to_query = timeout_add(ANVIL_QUERY_TIMEOUT_MSECS,
					       anvil_client_timeout, client);
	}
	return anvil_query;
}

void anvil_client_query_abort(struct anvil_client *client,
			      struct anvil_query **_query)
{
	struct anvil_query *query = *_query;
	struct anvil_query *const *queries;
	unsigned int i, count;

	*_query = NULL;

	count = aqueue_count(client->queries);
	queries = array_front(&client->queries_arr);
	for (i = 0; i < count; i++) {
		if (queries[aqueue_idx(client->queries, i)] == query) {
			query->callback = NULL;
			return;
		}
	}
	i_panic("anvil query to be aborted doesn't exist");
}

void anvil_client_cmd(struct anvil_client *client, const char *cmd)
{
	(void)anvil_client_send(client, cmd);
}

bool anvil_client_is_connected(struct anvil_client *client)
{
	return client->fd != -1;
}
