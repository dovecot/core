/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "imapc-seqmap.h"
#include "imapc-connection.h"
#include "imapc-client-private.h"

struct imapc_client_command_context {
	struct imapc_client_mailbox *box;

	imapc_command_callback_t *callback;
	void *context;
};

const struct imapc_capability_name imapc_capability_names[] = {
	{ "SASL-IR", IMAPC_CAPABILITY_SASL_IR },
	{ "LITERAL+", IMAPC_CAPABILITY_LITERALPLUS },
	{ "QRESYNC", IMAPC_CAPABILITY_QRESYNC },
	{ "IDLE", IMAPC_CAPABILITY_IDLE },

	{ "IMAP4REV1", IMAPC_CAPABILITY_IMAP4REV1 },
	{ NULL, 0 }
};

struct imapc_client *
imapc_client_init(const struct imapc_client_settings *set)
{
	struct imapc_client *client;
	pool_t pool;

	pool = pool_alloconly_create("imapc client", 1024);
	client = p_new(pool, struct imapc_client, 1);
	client->pool = pool;

	client->set.host = p_strdup(pool, set->host);
	client->set.port = set->port;
	client->set.master_user = p_strdup(pool, set->master_user);
	client->set.username = p_strdup(pool, set->username);
	client->set.password = p_strdup(pool, set->password);
	client->set.dns_client_socket_path =
		p_strdup(pool, set->dns_client_socket_path);
	p_array_init(&client->conns, pool, 8);
	return client;
}

void imapc_client_deinit(struct imapc_client **_client)
{
	struct imapc_client *client = *_client;
	struct imapc_client_connection **connp;

	*_client = NULL;

	array_foreach_modifiable(&client->conns, connp)
		imapc_connection_deinit(&(*connp)->conn);
	pool_unref(&client->pool);
}

void imapc_client_register_untagged(struct imapc_client *client,
				    imapc_untagged_callback_t *callback,
				    void *context)
{
	client->untagged_callback = callback;
	client->untagged_context = context;
}

void imapc_client_run(struct imapc_client *client)
{
	struct imapc_client_connection *const *connp;
	struct ioloop *prev_ioloop = current_ioloop;

	i_assert(client->ioloop == NULL);

	client->ioloop = io_loop_create();
	array_foreach(&client->conns, connp) {
		imapc_connection_ioloop_changed((*connp)->conn);
		imapc_connection_connect((*connp)->conn);
	}
	io_loop_run(client->ioloop);

	current_ioloop = prev_ioloop;
	array_foreach(&client->conns, connp)
		imapc_connection_ioloop_changed((*connp)->conn);

	current_ioloop = client->ioloop;
	io_loop_destroy(&client->ioloop);
}

void imapc_client_stop(struct imapc_client *client)
{
	if (client->ioloop != NULL)
		io_loop_stop(client->ioloop);
}

static struct imapc_client_connection *
imapc_client_add_connection(struct imapc_client *client)
{
	struct imapc_client_connection *conn;

	conn = i_new(struct imapc_client_connection, 1);
	conn->conn = imapc_connection_init(client);
	array_append(&client->conns, &conn, 1);
	return conn;
}

static struct imapc_connection *
imapc_client_find_connection(struct imapc_client *client)
{
	struct imapc_client_connection *const *connp;

	/* FIXME: stupid algorithm */
	if (array_count(&client->conns) == 0)
		return imapc_client_add_connection(client)->conn;
	connp = array_idx(&client->conns, 0);
	return (*connp)->conn;
}

void imapc_client_cmdf(struct imapc_client *client,
		       imapc_command_callback_t *callback, void *context,
		       const char *cmd_fmt, ...)
{
	struct imapc_connection *conn;
	va_list args;

	conn = imapc_client_find_connection(client);

	va_start(args, cmd_fmt);
	imapc_connection_cmdvf(conn, callback, context, cmd_fmt, args);
	va_end(args);
}

static struct imapc_client_connection *
imapc_client_get_unboxed_connection(struct imapc_client *client)
{
	struct imapc_client_connection *const *conns;
	unsigned int i, count;

	conns = array_get(&client->conns, &count);
	for (i = 0; i < count; i++) {
		if (conns[i]->box == NULL)
			return conns[i];
	}
	return imapc_client_add_connection(client);
}


struct imapc_client_mailbox *
imapc_client_mailbox_open(struct imapc_client *client, const char *name,
			  imapc_command_callback_t *callback, void *context,
			  void *untagged_box_context)
{
	struct imapc_client_mailbox *box;
	struct imapc_client_connection *conn;

	box = i_new(struct imapc_client_mailbox, 1);
	box->client = client;
	box->untagged_box_context = untagged_box_context;
	conn = imapc_client_get_unboxed_connection(client);
	conn->box = box;
	box->conn = conn->conn;
	box->seqmap = imapc_seqmap_init();

	imapc_connection_select(box, name, callback, context);
	return box;
}

void imapc_client_mailbox_close(struct imapc_client_mailbox **_box)
{
	struct imapc_client_mailbox *box = *_box;
	struct imapc_client_connection *const *connp;

	*_box = NULL;

	array_foreach(&box->client->conns, connp) {
		if ((*connp)->box == box) {
			(*connp)->box = NULL;
			break;
		}
	}

	imapc_connection_unselect(box);
	imapc_seqmap_deinit(&box->seqmap);
	i_free(box);
}

static void imapc_client_mailbox_cmd_cb(const struct imapc_command_reply *reply,
					void *context)
{
	struct imapc_client_command_context *ctx = context;

	ctx->box->pending_box_command_count--;

	ctx->callback(reply, ctx->context);
	i_free(ctx);
}

void imapc_client_mailbox_cmdf(struct imapc_client_mailbox *box,
			       imapc_command_callback_t *callback,
			       void *context, const char *cmd_fmt, ...)
{
	struct imapc_client_command_context *ctx;
	va_list args;

	ctx = i_new(struct imapc_client_command_context, 1);
	ctx->box = box;
	ctx->callback = callback;
	ctx->context = context;

	box->pending_box_command_count++;

	va_start(args, cmd_fmt);
	imapc_connection_cmdvf(box->conn, imapc_client_mailbox_cmd_cb,
			       ctx, cmd_fmt, args);
	va_end(args);
}

struct imapc_seqmap *
imapc_client_mailbox_get_seqmap(struct imapc_client_mailbox *box)
{
	return box->seqmap;
}

void imapc_client_mailbox_idle(struct imapc_client_mailbox *box)
{
	imapc_connection_idle(box->conn);
}

enum imapc_capability
imapc_client_get_capabilities(struct imapc_client *client)
{
	struct imapc_client_connection *const *connp;

	connp = array_idx(&client->conns, 0);
	return imapc_connection_get_capabilities((*connp)->conn);
}
