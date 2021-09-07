/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "connection.h"
#include "ioloop.h"
#include "istream.h"
#include "llist.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "indexer-queue.h"
#include "worker-connection.h"

#include <unistd.h>

#define INDEXER_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_PROTOCOL_MINOR_VERSION 0

#define INDEXER_MASTER_NAME "indexer-master-worker"
#define INDEXER_WORKER_NAME "indexer-worker-master"

struct worker_connection {
	struct connection conn;

	indexer_status_callback_t *callback;
	worker_available_callback_t *avail_callback;

	char *request_username;
	struct indexer_request *request;
};

static unsigned int worker_last_process_limit = 0;

static void worker_connection_call_callback(struct worker_connection *worker,
					    int percentage)
{
	if (worker->request != NULL)
		worker->callback(percentage, worker->request);
	if (percentage < 0 || percentage == 100)
		worker->request = NULL;
}

void worker_connection_destroy(struct connection *conn)
{
	struct worker_connection *worker =
		container_of(conn, struct worker_connection, conn);

	worker->request = NULL;
	i_free_and_null(worker->request_username);
	connection_deinit(conn);

	worker->avail_callback();
	i_free(conn);
}

static int
worker_connection_handshake_args(struct connection *conn, const char *const *args)
{
	unsigned int process_limit;
	int ret;
	if (!conn->version_received) {
		if ((ret = connection_handshake_args_default(conn, args)) < 1)
			return ret;
		/* we are not done yet */
		return 0;
	}
	if (str_to_uint(args[0], &process_limit) < 0 ||
	    process_limit == 0) {
		e_error(conn->event, "Worker sent invalid process limit '%s'",
			args[0]);
		return -1;
	}
	worker_last_process_limit = process_limit;
	return 1;
}

static int
worker_connection_input_args(struct connection *conn, const char *const *args)
{
	struct worker_connection *worker =
		container_of(conn, struct worker_connection, conn);
	int percentage;
	int ret = 1;

	if (str_to_int(args[0], &percentage) < 0 ||
	    percentage < -1 || percentage > 100) {
		e_error(conn->event, "Worker sent invalid progress '%s'", args[0]);
		return -1;
	}

	if (percentage < 0)
		ret = -1;

	worker_connection_call_callback(worker, percentage);
	if (worker->request == NULL) {
		/* disconnect after each request */
		ret = -1;
	}

	return ret;
}

bool worker_connection_is_connected(struct connection *conn)
{
	return !conn->disconnected;
}

unsigned int worker_connections_get_process_limit(void)
{
	return worker_last_process_limit;
}

void worker_connection_request(struct connection *conn,
			       struct indexer_request *request,
			       void *context)
{
	struct worker_connection *worker =
		container_of(conn, struct worker_connection, conn);

	i_assert(worker_connection_is_connected(conn));
	i_assert(context != NULL);
	i_assert(request->index || request->optimize);

	if (worker->request_username == NULL)
		worker->request_username = i_strdup(request->username);
	else {
		i_assert(strcmp(worker->request_username,
				request->username) == 0);
	}

	worker->request = request;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append_tabescaped(str, request->username);
		str_append_c(str, '\t');
		str_append_tabescaped(str, request->mailbox);
		str_append_c(str, '\t');
		if (request->session_id != NULL)
			str_append_tabescaped(str, request->session_id);
		str_printfa(str, "\t%u\t", request->max_recent_msgs);
		if (request->index)
			str_append_c(str, 'i');
		if (request->optimize)
			str_append_c(str, 'o');
		str_append_c(str, '\n');
		o_stream_nsend(conn->output, str_data(str), str_len(str));
	} T_END;
}

bool worker_connection_is_busy(struct connection *conn)
{
	struct worker_connection *worker =
		container_of(conn, struct worker_connection, conn);
	return worker->request != NULL;
}

const char *worker_connection_get_username(struct connection *conn)
{
	struct worker_connection *worker =
		container_of(conn, struct worker_connection, conn);
	return worker->request_username;
}

static const struct connection_vfuncs worker_connection_vfuncs = {
	.destroy = worker_connection_destroy,
	.input_args = worker_connection_input_args,
	.handshake_args = worker_connection_handshake_args,
};

static const struct connection_settings worker_connection_set = {
	.service_name_in = INDEXER_WORKER_NAME,
	.service_name_out = INDEXER_MASTER_NAME,
	.major_version = INDEXER_PROTOCOL_MAJOR_VERSION,
	.minor_version = INDEXER_PROTOCOL_MINOR_VERSION,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
};

struct connection_list *worker_connection_list_create(void)
{
	return connection_list_init(&worker_connection_set,
				    &worker_connection_vfuncs);
}

struct connection *
worker_connection_create(const char *socket_path,
			 indexer_status_callback_t *callback,
			 worker_available_callback_t *avail_callback,
			 struct connection_list *list)
{
	struct worker_connection *conn;

	conn = i_new(struct worker_connection, 1);
	conn->callback = callback;
	conn->avail_callback = avail_callback;
	connection_init_client_unix(list, &conn->conn, socket_path);

	return &conn->conn;
}
