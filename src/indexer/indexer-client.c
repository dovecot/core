/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "master-service.h"
#include "indexer-queue.h"
#include "indexer-client.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE (1024*64)

#define INDEXER_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_CLIENT_PROTOCOL_MINOR_VERSION 0

struct indexer_client {
	struct indexer_client *prev, *next;

	int refcount;
	struct indexer_queue *queue;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int version_received:1;
	unsigned int handshaked:1;
	unsigned int destroyed:1;
};

struct indexer_client_request {
	struct indexer_client *client;
	unsigned int tag;
};

struct indexer_client *clients = NULL;
static unsigned int clients_count = 0;

static void indexer_client_destroy(struct indexer_client *client);
static void indexer_client_ref(struct indexer_client *client);
static void indexer_client_unref(struct indexer_client *client);

static const char *const*
indexer_client_next_line(struct indexer_client *client)
{
	const char *line;
	char **args;
	unsigned int i;

	line = i_stream_next_line(client->input);
	if (line == NULL)
		return NULL;

	args = p_strsplit(pool_datastack_create(), line, "\t");
	for (i = 0; args[i] != NULL; i++)
		args[i] = str_tabunescape(args[i]);
	return (void *)args;
}

static int
indexer_client_request_queue(struct indexer_client *client, bool append,
			     const char *const *args, const char **error_r)
{
	struct indexer_client_request *ctx = NULL;
	unsigned int tag, max_recent_msgs;

	/* <tag> <user> <mailbox> [<max_recent_msgs>] */
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
	}

	if (tag != 0) {
		ctx = i_new(struct indexer_client_request, 1);
		ctx->client = client;
		ctx->tag = tag;
		indexer_client_ref(client);
	}

	indexer_queue_append(client->queue, append, args[1], args[2],
			     max_recent_msgs, ctx);
	o_stream_nsend_str(client->output, t_strdup_printf("%u\tOK\n", tag));
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
	o_stream_nsend_str(client->output, t_strdup_printf("%u\tOK\n", tag));
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
	else {
		*error_r = t_strconcat("Unknown command: ", cmd, NULL);
		return -1;
	}
}

static void indexer_client_input(struct indexer_client *client)
{
	const char *line, *const *args, *error;

	switch (i_stream_read(client->input)) {
	case -2:
		i_error("BUG: Client connection sent too much data");
		indexer_client_destroy(client);
		return;
	case -1:
		indexer_client_destroy(client);
		return;
	}

	if (!client->version_received) {
		if ((line = i_stream_next_line(client->input)) == NULL)
			return;

		if (!version_string_verify(line, "indexer",
				INDEXER_CLIENT_PROTOCOL_MAJOR_VERSION)) {
			i_error("Client not compatible with this server "
				"(mixed old and new binaries?)");
			indexer_client_destroy(client);
			return;
		}
		client->version_received = TRUE;
	}

	while ((args = indexer_client_next_line(client)) != NULL) {
		if (args[0] != NULL) {
			if (indexer_client_request(client, args, &error) < 0) {
				i_error("Client input error: %s", error);
				indexer_client_destroy(client);
				break;
			}
		}
	}
}

void indexer_client_status_callback(int percentage, void *context)
{
	struct indexer_client_request *ctx = context;

	T_BEGIN {
		o_stream_nsend_str(ctx->client->output,
			t_strdup_printf("%u\t%d\n", ctx->tag, percentage));
	} T_END;
	if (percentage < 0 || percentage == 100) {
		indexer_client_unref(ctx->client);
		i_free(ctx);
	}
}

struct indexer_client *
indexer_client_create(int fd, struct indexer_queue *queue)
{
	struct indexer_client *client;

	client = i_new(struct indexer_client, 1);
	client->refcount = 1;
	client->queue = queue;
	client->fd = fd;
	client->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);
	client->io = io_add(fd, IO_READ, indexer_client_input, client);

	DLLIST_PREPEND(&clients, client);
	clients_count++;
	indexer_refresh_proctitle();
	return client;
}

static void indexer_client_destroy(struct indexer_client *client)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	DLLIST_REMOVE(&clients, client);

	io_remove(&client->io);
	i_stream_close(client->input);
	o_stream_close(client->output);
	if (close(client->fd) < 0)
		i_error("close(client) failed: %m");
	client->fd = -1;
	indexer_client_unref(client);

	clients_count--;
	master_service_client_connection_destroyed(master_service);
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
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	i_free(client);
}

unsigned int indexer_clients_get_count(void)
{
	return clients_count;
}

void indexer_clients_destroy_all(void)
{
	while (clients != NULL)
		indexer_client_destroy(clients);
}
