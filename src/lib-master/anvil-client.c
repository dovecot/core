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

struct anvil_query {
	anvil_callback_t *callback;
	void *context;
};

struct anvil_client {
	struct connection conn;
	struct timeout *to_query;

	struct timeout *to_reconnect;
	time_t last_reconnect;

	ARRAY(struct anvil_query *) queries_arr;
	struct aqueue *queries;

	bool (*reconnect_callback)(void);
	enum anvil_client_flags flags;
	bool deinitializing;
};

#define ANVIL_INBUF_SIZE 1024
#define ANVIL_RECONNECT_MIN_SECS 5
#define ANVIL_QUERY_TIMEOUT_MSECS (1000*5)

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
anvil_client_init(const char *path, bool (*reconnect_callback)(void),
		  enum anvil_client_flags flags)
{
	struct anvil_client *client;

	if (anvil_connections == NULL) {
		anvil_connections = connection_list_init(&anvil_connections_set,
							 &anvil_connections_vfuncs);
	}

	client = i_new(struct anvil_client, 1);
	connection_init_client_unix(anvil_connections, &client->conn, path);
	client->reconnect_callback = reconnect_callback;
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

static void anvil_client_start_multiplex_input(struct anvil_client *client)
{
	struct istream *orig_input = client->conn.input;
	client->conn.input = i_stream_create_multiplex(orig_input, ANVIL_INBUF_SIZE);
	i_stream_unref(&orig_input);

	connection_streams_changed(&client->conn);
}

static void
anvil_client_start_multiplex_output(struct anvil_client *client)
{
	struct ostream *orig_output = client->conn.output;
	client->conn.output = o_stream_create_multiplex(orig_output, SIZE_MAX);
	o_stream_set_no_error_handling(client->conn.output, TRUE);
	o_stream_unref(&orig_output);
}

static void anvil_client_reconnect(struct anvil_client *client)
{
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
					    anvil_client_reconnect, client);
		}
	} else {
		client->last_reconnect = ioloop_time;
		(void)anvil_client_connect(client, FALSE);
	}
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
	i_free(query);
	aqueue_delete_tail(client->queries);

	if (client->to_query != NULL) {
		if (aqueue_count(client->queries) == 0)
			timeout_remove(&client->to_query);
		else
			timeout_reset(client->to_query);
	}
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

	const char *anvil_handshake =
		t_strdup_printf("%s\t%s\n",
				master_service_get_name(master_service),
				my_pid);
	o_stream_nsend_str(client->conn.output, anvil_handshake);
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
		i_free(query);
		aqueue_delete_tail(client->queries);
	}
	timeout_remove(&client->to_query);
}

static void anvil_client_destroy(struct connection *conn)
{
	struct anvil_client *client =
		container_of(conn, struct anvil_client, conn);

	connection_disconnect(&client->conn);
	anvil_client_cancel_queries(client);
	timeout_remove(&client->to_reconnect);

	if (!client->deinitializing)
		anvil_client_reconnect(client);
}

static void anvil_client_timeout(struct anvil_client *client)
{
	i_assert(aqueue_count(client->queries) > 0);

	e_error(client->conn.event,
		"Anvil queries timed out after %u secs - aborting queries",
		ANVIL_QUERY_TIMEOUT_MSECS/1000);
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
	return !client->conn.disconnected;
}
