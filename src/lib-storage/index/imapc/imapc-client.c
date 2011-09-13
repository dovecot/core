/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "safe-mkstemp.h"
#include "iostream-ssl.h"
#include "imapc-msgmap.h"
#include "imapc-connection.h"
#include "imapc-client-private.h"

#include <unistd.h>

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
	{ "UIDPLUS", IMAPC_CAPABILITY_UIDPLUS },
	{ "AUTH=PLAIN", IMAPC_CAPABILITY_AUTH_PLAIN },
	{ "STARTTLS", IMAPC_CAPABILITY_STARTTLS },

	{ "IMAP4REV1", IMAPC_CAPABILITY_IMAP4REV1 },
	{ NULL, 0 }
};

struct imapc_client *
imapc_client_init(const struct imapc_client_settings *set)
{
	struct imapc_client *client;
	struct ssl_iostream_settings ssl_set;
	const char *source;
	pool_t pool;

	pool = pool_alloconly_create("imapc client", 1024);
	client = p_new(pool, struct imapc_client, 1);
	client->pool = pool;

	client->set.debug = set->debug;
	client->set.host = p_strdup(pool, set->host);
	client->set.port = set->port;
	client->set.master_user = p_strdup(pool, set->master_user);
	client->set.username = p_strdup(pool, set->username);
	client->set.password = p_strdup(pool, set->password);
	client->set.dns_client_socket_path =
		p_strdup(pool, set->dns_client_socket_path);
	client->set.temp_path_prefix =
		p_strdup(pool, set->temp_path_prefix);

	if (set->ssl_mode != IMAPC_CLIENT_SSL_MODE_NONE) {
		client->set.ssl_mode = set->ssl_mode;
		client->set.ssl_ca_dir = p_strdup(pool, set->ssl_ca_dir);

		memset(&ssl_set, 0, sizeof(ssl_set));
		ssl_set.ca_dir = set->ssl_ca_dir;
		ssl_set.verify_remote_cert = TRUE;

		source = t_strdup_printf("%s:%u", set->host, set->port);
		if (ssl_iostream_context_init_client(source, &ssl_set,
						     &client->ssl_ctx) < 0) {
			i_error("imapc(%s): Couldn't initialize SSL context",
				source);
		}
	}

	p_array_init(&client->conns, pool, 8);
	return client;
}

void imapc_client_deinit(struct imapc_client **_client)
{
	struct imapc_client *client = *_client;
	struct imapc_client_connection **connp;

	*_client = NULL;

	if (client->ssl_ctx != NULL)
		ssl_iostream_context_deinit(&client->ssl_ctx);
	array_foreach_modifiable(&client->conns, connp) {
		imapc_connection_deinit(&(*connp)->conn);
		i_free(*connp);
	}
	pool_unref(&client->pool);
}

void imapc_client_register_untagged(struct imapc_client *client,
				    imapc_untagged_callback_t *callback,
				    void *context)
{
	client->untagged_callback = callback;
	client->untagged_context = context;
}

void imapc_client_run_pre(struct imapc_client *client)
{
	struct imapc_client_connection *const *connp;
	struct ioloop *prev_ioloop = current_ioloop;
	bool handle_pending = client->stop_now;

	i_assert(client->ioloop == NULL);

	client->stop_now = FALSE;

	client->ioloop = io_loop_create();
	io_loop_set_running(client->ioloop);

	array_foreach(&client->conns, connp) {
		imapc_connection_ioloop_changed((*connp)->conn);
		imapc_connection_connect((*connp)->conn);
		if (handle_pending)
			imapc_connection_input_pending((*connp)->conn);
	}

	if (io_loop_is_running(client->ioloop))
		io_loop_run(client->ioloop);
	current_ioloop = prev_ioloop;
}

void imapc_client_run_post(struct imapc_client *client)
{
	struct imapc_client_connection *const *connp;
	struct ioloop *ioloop = client->ioloop;

	client->ioloop = NULL;
	array_foreach(&client->conns, connp)
		imapc_connection_ioloop_changed((*connp)->conn);

	current_ioloop = ioloop;
	io_loop_destroy(&ioloop);
}

void imapc_client_stop(struct imapc_client *client)
{
	if (client->ioloop != NULL)
		io_loop_stop(client->ioloop);
}

bool imapc_client_is_running(struct imapc_client *client)
{
	return client->ioloop != NULL;
}

void imapc_client_stop_now(struct imapc_client *client)
{
	client->stop_now = TRUE;
	imapc_client_stop(client);
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
	imapc_connection_cmdvf(conn, FALSE, callback, context, cmd_fmt, args);
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
imapc_client_mailbox_open(struct imapc_client *client,
			  const char *name, bool examine,
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
	box->msgmap = imapc_msgmap_init();

	imapc_connection_select(box, name, examine, callback, context);
	return box;
}

void imapc_client_mailbox_disconnect(struct imapc_client_mailbox *box)
{
	if (box->conn != NULL)
		imapc_connection_disconnect(box->conn);
}

void imapc_client_mailbox_close(struct imapc_client_mailbox **_box)
{
	struct imapc_client_mailbox *box = *_box;
	struct imapc_client_connection *const *connp;

	array_foreach(&box->client->conns, connp) {
		if ((*connp)->box == box) {
			(*connp)->box = NULL;
			break;
		}
	}

	if (box->conn != NULL)
		imapc_connection_unselect(box);
	imapc_msgmap_deinit(&box->msgmap);
	i_free(box);

	/* set this only after unselect, which may cancel some commands that
	   reference this box */
	*_box = NULL;
}

static void imapc_client_mailbox_cmd_cb(const struct imapc_command_reply *reply,
					void *context)
{
	struct imapc_client_command_context *ctx = context;

	ctx->box->pending_box_command_count--;

	ctx->callback(reply, ctx->context);
	i_free(ctx);
}

static struct imapc_client_command_context *
imapc_client_mailbox_cmd_common(struct imapc_client_mailbox *box,
				imapc_command_callback_t *callback,
				void *context)
{
	struct imapc_client_command_context *ctx;

	ctx = i_new(struct imapc_client_command_context, 1);
	ctx->box = box;
	ctx->callback = callback;
	ctx->context = context;

	box->pending_box_command_count++;
	return ctx;
}

static bool
imapc_client_mailbox_is_selected(struct imapc_client_mailbox *box,
				 struct imapc_command_reply *reply_r)
{
	struct imapc_client_mailbox *selected_box;

	selected_box = box->conn == NULL ? NULL :
		imapc_connection_get_mailbox(box->conn);
	if (selected_box == box)
		return TRUE;

	memset(reply_r, 0, sizeof(*reply_r));
	reply_r->state = IMAPC_COMMAND_STATE_DISCONNECTED;
	if (selected_box == NULL) {
		reply_r->text_full = "Disconnected from server";
	} else {
		i_error("imapc: Selected mailbox changed unexpectedly");
		reply_r->text_full = "Internal error";
	}
	reply_r->text_without_resp = reply_r->text_full;

	box->conn = NULL;
	return FALSE;
}

void imapc_client_mailbox_cmd(struct imapc_client_mailbox *box,
			      const char *cmd,
			      imapc_command_callback_t *callback,
			      void *context)
{
	struct imapc_client_command_context *ctx;
	struct imapc_command_reply reply;

	if (!imapc_client_mailbox_is_selected(box, &reply)) {
		callback(&reply, context);
		return;
	}

	ctx = imapc_client_mailbox_cmd_common(box, callback, context);
	imapc_connection_cmd(box->conn, TRUE, cmd,
			     imapc_client_mailbox_cmd_cb, ctx);
}

void imapc_client_mailbox_cmdf(struct imapc_client_mailbox *box,
			       imapc_command_callback_t *callback,
			       void *context, const char *cmd_fmt, ...)
{
	struct imapc_client_command_context *ctx;
	va_list args;
	struct imapc_command_reply reply;

	if (!imapc_client_mailbox_is_selected(box, &reply)) {
		callback(&reply, context);
		return;
	}

	ctx = imapc_client_mailbox_cmd_common(box, callback, context);
	va_start(args, cmd_fmt);
	imapc_connection_cmdvf(box->conn, TRUE, imapc_client_mailbox_cmd_cb,
			       ctx, cmd_fmt, args);
	va_end(args);
}

struct imapc_msgmap *
imapc_client_mailbox_get_msgmap(struct imapc_client_mailbox *box)
{
	return box->msgmap;
}

void imapc_client_mailbox_idle(struct imapc_client_mailbox *box)
{
	struct imapc_command_reply reply;

	if (imapc_client_mailbox_is_selected(box, &reply))
		imapc_connection_idle(box->conn);
}

bool imapc_client_mailbox_is_connected(struct imapc_client_mailbox *box)
{
	struct imapc_command_reply reply;

	return imapc_client_mailbox_is_selected(box, &reply);
}

enum imapc_capability
imapc_client_get_capabilities(struct imapc_client *client)
{
	struct imapc_client_connection *const *connp;

	connp = array_idx(&client->conns, 0);
	return imapc_connection_get_capabilities((*connp)->conn);
}

int imapc_client_create_temp_fd(struct imapc_client *client,
				const char **path_r)
{
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, client->set.temp_path_prefix);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		(void)close(fd);
		return -1;
	}
	*path_r = str_c(path);
	return fd;
}
