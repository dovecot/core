/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "master-service.h"
#include "indexer-queue.h"
#include "indexer-client.h"

#include <unistd.h>

#define MAX_INBUF_SIZE (1024*64)

#define INDEXER_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_CLIENT_PROTOCOL_MINOR_VERSION 0

struct indexer_client {
	struct connection conn;

	int refcount;
	struct indexer_queue *queue;
};

struct indexer_client_request {
	struct indexer_client *client;
	unsigned int tag;
};

static void indexer_client_destroy(struct connection *conn);
static void indexer_client_ref(struct indexer_client *client);
static void indexer_client_unref(struct indexer_client *client);

static int
indexer_client_request_queue(struct indexer_client *client, bool append,
			     const char *const *args, const char **error_r)
{
	struct indexer_client_request *ctx = NULL;
	const char *session_id = NULL;
	unsigned int tag, max_recent_msgs;

	/* <tag> <user> <mailbox> [<max_recent_msgs> [<session ID>]] */
	if (str_array_length(args) < 3) {
		*error_r = "Wrong parameter count";
		return -1;
	}
	if (str_to_uint(args[0], &tag) < 0) {
		*error_r = "Invalid tag";
		return -1;
	}
	if (args[3] == NULL)
		max_recent_msgs = 0;
	else if (str_to_uint(args[3], &max_recent_msgs) < 0) {
		*error_r = "Invalid max_recent_msgs";
		return -1;
	} else {
		session_id = args[4];
	}

	if (tag != 0) {
		ctx = i_new(struct indexer_client_request, 1);
		ctx->client = client;
		ctx->tag = tag;
		indexer_client_ref(client);
	}

	indexer_queue_append(client->queue, append, args[1], args[2],
			     session_id, max_recent_msgs, ctx);
	o_stream_nsend_str(client->conn.output, t_strdup_printf("%u\tOK\n", tag));
	return 0;
}

static int
indexer_client_request_optimize(struct indexer_client *client,
				const char *const *args, const char **error_r)
{
	struct indexer_client_request *ctx = NULL;
	unsigned int tag;

	/* <tag> <user> <mailbox> */
	if (str_array_length(args) != 3) {
		*error_r = "Wrong parameter count";
		return -1;
	}
	if (str_to_uint(args[0], &tag) < 0) {
		*error_r = "Invalid tag";
		return -1;
	}

	if (tag != 0) {
		ctx = i_new(struct indexer_client_request, 1);
		ctx->client = client;
		ctx->tag = tag;
		indexer_client_ref(client);
	}

	indexer_queue_append_optimize(client->queue, args[1], args[2], ctx);
	o_stream_nsend_str(client->conn.output, t_strdup_printf("%u\tOK\n", tag));
	return 0;
}

static int
indexer_client_request_remove(struct indexer_client *client,
			      const char *const *args, const char **error_r)
{
	unsigned int tag;

	/* <tag> <user mask> [<mailbox mask>] */
	if (str_array_length(args) < 2) {
		*error_r = "Wrong parameter count";
		return -1;
	}
	if (str_to_uint(args[0], &tag) < 0) {
		*error_r = "Invalid tag";
		return -1;
	}
	const char *user_mask = args[1];
	const char *mailbox_mask = args[2];

	if (wildcard_is_literal(user_mask))
		indexer_queue_cancel(client->queue, user_mask, mailbox_mask);
	else {
		struct indexer_request *request;
		struct indexer_queue_iter *iter =
			indexer_queue_iter_init(client->queue, FALSE);
		while ((request = indexer_queue_iter_next(iter)) != NULL) {
			if (wildcard_match(request->username, user_mask)) {
				indexer_queue_cancel(client->queue,
					request->username, mailbox_mask);
			}
		}
		indexer_queue_iter_deinit(&iter);
	}
	o_stream_nsend_str(client->conn.output, t_strdup_printf("%u\tOK\n", tag));
	return 0;
}

static void
indexer_client_request_list_write(string_t *str,
				  struct indexer_request *request)
{
	str_append_tabescaped(str, request->username);
	str_append_c(str, '\t');
	str_append_tabescaped(str, request->mailbox);
	str_append_c(str, '\t');
	if (request->session_id != NULL)
		str_append_tabescaped(str, request->session_id);
	str_printfa(str, "\t%u\t", request->max_recent_msgs);
	switch (request->type) {
	case INDEXER_REQUEST_TYPE_INDEX:
		str_append_c(str, 'i');
		break;
	case INDEXER_REQUEST_TYPE_OPTIMIZE:
		str_append_c(str, 'o');
		break;
	}
	str_append_c(str, '\t');
	if (request->working)
		str_append_c(str, 'w');
	if (request->reindex_head)
		str_append_c(str, 'h');
	if (request->reindex_tail)
		str_append_c(str, 't');
}

static int
indexer_client_request_list(struct indexer_client *client,
			    const char *const *args, const char **error_r)
{
	const char *mask;
	unsigned int tag;
	bool only_working;

	/* <tag> <type> [<user mask>] */
	if (str_array_length(args) < 2) {
		*error_r = "Wrong parameter count";
		return -1;
	}
	if (str_to_uint(args[0], &tag) < 0) {
		*error_r = "Invalid tag";
		return -1;
	}
	if (strcmp(args[1], "all") == 0)
		only_working = FALSE;
	else if (strcmp(args[1], "working") == 0)
		only_working = TRUE;
	else {
		*error_r = "Invalid type";
		return -1;
	}
	mask = args[2];

	string_t *str = t_str_new(128);
	struct indexer_request *request;
	struct indexer_queue_iter *iter =
		indexer_queue_iter_init(client->queue, only_working);
	while ((request = indexer_queue_iter_next(iter)) != NULL) {
		if (mask != NULL && !wildcard_match(request->username, mask))
			continue;

		str_truncate(str, 0);
		str_printfa(str, "%u\t", tag);
		indexer_client_request_list_write(str, request);
		str_append_c(str, '\n');
		o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	}
	indexer_queue_iter_deinit(&iter);

	str_truncate(str, 0);
	str_printfa(str, "%u\n", tag);
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	return 0;
}

static int
indexer_client_request(struct indexer_client *client,
		       const char *const *args, const char **error_r)
{
	const char *cmd = args[0];

	args++;

	if (strcmp(cmd, "APPEND") == 0)
		return indexer_client_request_queue(client, TRUE, args, error_r);
	else if (strcmp(cmd, "PREPEND") == 0)
		return indexer_client_request_queue(client, FALSE, args, error_r);
	else if (strcmp(cmd, "OPTIMIZE") == 0)
		return indexer_client_request_optimize(client, args, error_r);
	else if (strcmp(cmd, "REMOVE") == 0)
		return indexer_client_request_remove(client, args, error_r);
	else if (strcmp(cmd, "LIST") == 0)
		return indexer_client_request_list(client, args, error_r);
	else {
		*error_r = t_strconcat("Unknown command: ", cmd, NULL);
		return -1;
	}
}

static int
indexer_client_input_args(struct connection *conn, const char *const *args)
{
	struct indexer_client *client =
		container_of(conn, struct indexer_client, conn);
	const char *error;

	if (indexer_client_request(client, args, &error) < 0) {
		e_error(conn->event, "Client input error: %s", error);
		return -1;
	}
	return 1;
}

void indexer_client_status_callback(int percentage, void *context)
{
	struct indexer_client_request *ctx = context;

	if (ctx->client->conn.output != NULL) T_BEGIN {
		o_stream_nsend_str(ctx->client->conn.output,
			t_strdup_printf("%u\t%d\n", ctx->tag, percentage));
	} T_END;
	if (percentage < 0 || percentage == 100) {
		indexer_client_unref(ctx->client);
		i_free(ctx);
	}
}

static struct connection_list *indexer_client_list = NULL;

static const struct connection_vfuncs indexer_client_vfuncs = {
	.destroy = indexer_client_destroy,
	.input_args = indexer_client_input_args,
};

static const struct connection_settings indexer_client_set = {
	.service_name_in = "indexer-client",
	.service_name_out = "indexer-server",
	.major_version = INDEXER_CLIENT_PROTOCOL_MAJOR_VERSION,
	.minor_version = INDEXER_CLIENT_PROTOCOL_MINOR_VERSION,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
};


void indexer_client_create(struct master_service_connection *conn,
			   struct indexer_queue *queue)
{
	struct indexer_client *client;

	if (indexer_client_list == NULL) {
		indexer_client_list =
			connection_list_init(&indexer_client_set,
					     &indexer_client_vfuncs);
	}

	client = i_new(struct indexer_client, 1);
	client->refcount = 1;
	client->queue = queue;
	connection_init_server(indexer_client_list, &client->conn,
			       conn->name, conn->fd, conn->fd);
	indexer_refresh_proctitle();
}

static void indexer_client_destroy(struct connection *conn)
{
	struct indexer_client *client =
		container_of(conn, struct indexer_client, conn);
	connection_deinit(&client->conn);
	master_service_client_connection_destroyed(master_service);
	indexer_client_unref(client);
	indexer_refresh_proctitle();
}

static void indexer_client_ref(struct indexer_client *client)
{
	i_assert(client->refcount > 0);

	client->refcount++;
}

static void indexer_client_unref(struct indexer_client *client)
{
	i_assert(client->refcount > 0);

	if (--client->refcount > 0)
		return;
	i_free(client);
}

unsigned int indexer_clients_get_count(void)
{
	if (indexer_client_list == NULL)
		return 0;
	return indexer_client_list->connections_count;
}

void indexer_clients_destroy_all(void)
{
	connection_list_deinit(&indexer_client_list);
}
