/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "istream-multiplex.h"
#include "ostream-multiplex.h"
#include "hostpid.h"
#include "array.h"
#include "aqueue.h"
#include "strescape.h"
#include "master-service.h"
#include "anvil-client.h"

#define ANVIL_CMD_CHANNEL_ID 1

struct anvil_query {
	struct anvil_client *client;
	struct timeout *to;
	unsigned int timeout_msecs;

	anvil_callback_t *callback;
	void *context;
};

struct anvil_client {
	struct connection conn;
	struct timeout *to_cancel;

	struct timeout *to_reconnect;
	time_t last_reconnect;

	ARRAY(struct anvil_query *) queries_arr;
	struct aqueue *queries;

	struct istream *cmd_input;
	struct ostream *cmd_output;
	struct io *cmd_io;

	struct anvil_client_callbacks callbacks;
	enum anvil_client_flags flags;
	bool deinitializing;
	bool reply_pending:1;
};

#define ANVIL_INBUF_SIZE 1024
#define ANVIL_RECONNECT_MIN_SECS 5

static void anvil_client_destroy(struct connection *conn);
static int anvil_client_input_line(struct connection *conn, const char *line);

static struct connection_list *anvil_connections;

static struct connection_settings anvil_connections_set = {
	.major_version = 2,
	.minor_version = 0,
	.service_name_out = "anvil-client",
	.service_name_in = "anvil-server",

	.input_max_size = ANVIL_INBUF_SIZE,
	.output_max_size = SIZE_MAX,

	.client = TRUE,
};

static struct connection_vfuncs anvil_connections_vfuncs = {
	.destroy = anvil_client_destroy,
	.input_line = anvil_client_input_line,
};

struct anvil_client *
anvil_client_init(const char *path,
		  const struct anvil_client_callbacks *callbacks,
		  enum anvil_client_flags flags)
{
	struct anvil_client *client;

	if (anvil_connections == NULL) {
		anvil_connections = connection_list_init(&anvil_connections_set,
							 &anvil_connections_vfuncs);
	}

	client = i_new(struct anvil_client, 1);
	connection_init_client_unix(anvil_connections, &client->conn, path);
	if (callbacks != NULL)
		client->callbacks = *callbacks;
	client->flags = flags;
	i_array_init(&client->queries_arr, 32);
	client->queries = aqueue_init(&client->queries_arr.arr);
	return client;
}

void anvil_client_deinit(struct anvil_client **_client)
{
	struct anvil_client *client = *_client;

	*_client = NULL;

	client->deinitializing = TRUE;
	anvil_client_destroy(&client->conn);

	array_free(&client->queries_arr);
	aqueue_deinit(&client->queries);
	i_assert(client->to_reconnect == NULL);
	connection_deinit(&client->conn);
	i_free(client);

	if (anvil_connections->connections == NULL)
		connection_list_deinit(&anvil_connections);
}

static void anvil_client_cmd_pending_input(struct anvil_client *client)
{
	const char *line, *cmd, *const *args;

	while (!client->reply_pending &&
	       (line = i_stream_next_line(client->cmd_input)) != NULL) T_BEGIN {
		args = t_strsplit_tabescaped(line);
		cmd = args[0]; args++;
		if (cmd == NULL) {
			o_stream_nsend_str(client->cmd_output,
					   "-Empty command\n");
		} else {
			/* Set reply_pending before the callback, since it
			   can immediately call anvil_client_send_reply() */
			client->reply_pending = TRUE;
			if (!client->callbacks.command(cmd, args)) {
				client->reply_pending = FALSE;
				o_stream_nsend_str(client->cmd_output,
						   "-Unknown command\n");
			}
		}
	} T_END;
	if (client->reply_pending)
		io_remove(&client->cmd_io);
}

static void anvil_client_cmd_input(struct anvil_client *client)
{
	anvil_client_cmd_pending_input(client);
	if (connection_input_read_stream(&client->conn, client->cmd_input) < 0)
		return;
	anvil_client_cmd_pending_input(client);
}

static void anvil_client_start_multiplex_input(struct anvil_client *client)
{
	struct istream *orig_input = client->conn.input;
	client->conn.input = i_stream_create_multiplex(orig_input, ANVIL_INBUF_SIZE);
	i_stream_unref(&orig_input);

	connection_streams_changed(&client->conn);

	client->cmd_input = i_stream_multiplex_add_channel(client->conn.input,
							   ANVIL_CMD_CHANNEL_ID);
	client->cmd_io = io_add_istream(client->cmd_input,
					anvil_client_cmd_input, client);
}

static void
anvil_client_start_multiplex_output(struct anvil_client *client)
{
	struct ostream *orig_output = client->conn.output;
	client->conn.output = o_stream_create_multiplex(orig_output, SIZE_MAX);
	o_stream_set_no_error_handling(client->conn.output, TRUE);
	o_stream_unref(&orig_output);

	client->cmd_output = o_stream_multiplex_add_channel(client->conn.output,
							    ANVIL_CMD_CHANNEL_ID);
}

static void anvil_client_reconnect(struct anvil_client *client)
{
	if (client->callbacks.reconnect != NULL) {
		if (!client->callbacks.reconnect()) {
			/* no reconnection */
			return;
		}
	}

	if (ioloop_time - client->last_reconnect < ANVIL_RECONNECT_MIN_SECS) {
		if (client->to_reconnect == NULL) {
			client->to_reconnect =
				timeout_add(ANVIL_RECONNECT_MIN_SECS*1000,
					    anvil_client_reconnect, client);
		}
	} else {
		client->last_reconnect = ioloop_time;
		(void)anvil_client_connect(client, FALSE);
	}
}

static void anvil_query_free(struct anvil_query **_query)
{
	struct anvil_query *query = *_query;

	*_query = NULL;
	timeout_remove(&query->to);
	i_free(query);
}

static int anvil_client_input_line(struct connection *conn, const char *line)
{
	struct anvil_client *client =
		container_of(conn, struct anvil_client, conn);
	struct anvil_query *const *queries;
	struct anvil_query *query;
	unsigned int count;

	if (!conn->version_received) {
		const char *const *args = t_strsplit_tabescaped(line);
		if (connection_handshake_args_default(conn, args) < 0) {
			conn->disconnect_reason =
				CONNECTION_DISCONNECT_HANDSHAKE_FAILED;
			return -1;
		}
		if (client->callbacks.command != NULL)
			anvil_client_start_multiplex_input(client);
		return 1;
	}

	if (aqueue_count(client->queries) == 0) {
		e_error(client->conn.event, "Unexpected input: %s", line);
		return -1;
	}

	queries = array_get(&client->queries_arr, &count);
	query = queries[aqueue_idx(client->queries, 0)];
	if (query->callback != NULL) T_BEGIN {
		query->callback(line, query->context);
	} T_END;
	anvil_query_free(&query);
	aqueue_delete_tail(client->queries);
	return 1;
}

int anvil_client_connect(struct anvil_client *client, bool retry)
{
	int ret;

	i_assert(client->conn.fd_in == -1);

	ret = retry ? connection_client_connect_with_retries(&client->conn, 5000) :
		connection_client_connect(&client->conn);
	if (ret < 0) {
		if (errno != ENOENT ||
		    (client->flags & ANVIL_CLIENT_FLAG_HIDE_ENOENT) == 0) {
			e_error(client->conn.event,
				"net_connect_unix(%s) failed: %m",
				client->conn.base_name);
		}
		return -1;
	}
	timeout_remove(&client->to_reconnect);

	const char *anvil_handshake = client->callbacks.command == NULL ? "\n" :
		t_strdup_printf("%s\t%s\n",
				master_service_get_name(master_service),
				my_pid);
	o_stream_nsend_str(client->conn.output, anvil_handshake);
	if (client->callbacks.command != NULL)
		anvil_client_start_multiplex_output(client);
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
		anvil_query_free(&query);
		aqueue_delete_tail(client->queries);
	}
	timeout_remove(&client->to_cancel);
}

static void anvil_client_destroy(struct connection *conn)
{
	struct anvil_client *client =
		container_of(conn, struct anvil_client, conn);

	io_remove(&client->cmd_io);
	i_stream_destroy(&client->cmd_input);
	o_stream_destroy(&client->cmd_output);
	connection_disconnect(&client->conn);
	anvil_client_cancel_queries(client);
	timeout_remove(&client->to_reconnect);

	if (!client->deinitializing)
		anvil_client_reconnect(client);
}

static void anvil_client_timeout(struct anvil_query *anvil_query)
{
	struct anvil_client *client = anvil_query->client;

	i_assert(aqueue_count(client->queries) > 0);

	e_error(client->conn.event,
		"Anvil queries timed out after %u.%03u secs - aborting queries",
		anvil_query->timeout_msecs / 1000,
		anvil_query->timeout_msecs % 1000);
	/* perhaps reconnect helps */
	anvil_client_destroy(&client->conn);
}

static int anvil_client_send(struct anvil_client *client, const char *cmd)
{
	struct const_iovec iov[2];

	if (client->conn.disconnected) {
		if (anvil_client_connect(client, FALSE) < 0)
			return -1;
	}

	iov[0].iov_base = cmd;
	iov[0].iov_len = strlen(cmd);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	o_stream_nsendv(client->conn.output, iov, 2);
	return 0;
}

#undef anvil_client_query
struct anvil_query *
anvil_client_query(struct anvil_client *client, const char *query,
		   unsigned int timeout_msecs,
		   anvil_callback_t *callback, void *context)
{
	struct anvil_query *anvil_query;

	i_assert(timeout_msecs > 0);

	anvil_query = i_new(struct anvil_query, 1);
	anvil_query->client = client;
	anvil_query->timeout_msecs = timeout_msecs;
	anvil_query->callback = callback;
	anvil_query->context = context;
	aqueue_append(client->queries, &anvil_query);
	if (anvil_client_send(client, query) < 0) {
		/* connection failure. add a delayed failure callback.
		   the caller may not expect the callback to be called
		   immediately. */
		if (client->to_cancel == NULL) {
			client->to_cancel =
				timeout_add_short(0,
					anvil_client_cancel_queries, client);
		}
	} else {
		anvil_query->to = timeout_add(timeout_msecs,
					      anvil_client_timeout, anvil_query);
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

void anvil_client_send_reply(struct anvil_client *client, const char *reply)
{
	i_assert(client->reply_pending);

	struct const_iovec iov[] = {
		{ reply, strlen(reply) },
		{ "\n", 1 }
	};
	o_stream_nsendv(client->cmd_output, iov, N_ELEMENTS(iov));

	if (client->cmd_io == NULL) {
		/* asynchronous reply from cmd_callback() */
		client->cmd_io = io_add_istream(client->cmd_input,
						anvil_client_cmd_input, client);
		i_stream_set_input_pending(client->cmd_input, TRUE);
	}
	client->reply_pending = FALSE;
}

void anvil_client_cmd(struct anvil_client *client, const char *cmd)
{
	(void)anvil_client_send(client, cmd);
}

bool anvil_client_is_connected(struct anvil_client *client)
{
	return !client->conn.disconnected;
}
