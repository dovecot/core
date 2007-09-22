/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "dict.h"
#include "dict-client.h"
#include "dict-server.h"

#include <stdlib.h>
#include <unistd.h>

struct dict_server_transaction {
	unsigned int id;
	struct dict_transaction_context *ctx;
};

struct dict_client_connection {
	struct dict_server *server;

	char *username;
	char *name;
	struct dict *dict;
	enum dict_data_type value_type;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	/* There are only a few transactions per client, so keeping them in
	   array is fast enough */
	ARRAY_DEFINE(transactions, struct dict_server_transaction);
};

struct dict_server {
	char *path;
	int fd;
	struct io *io;
};

struct dict_client_cmd {
	int cmd;
	int (*func)(struct dict_client_connection *conn, const char *line);
};

static void dict_client_connection_deinit(struct dict_client_connection *conn);

static int cmd_lookup(struct dict_client_connection *conn, const char *line)
{
	const char *reply;
	const char *value;
	int ret;

	/* <key> */
	ret = dict_lookup(conn->dict, pool_datastack_create(), line, &value);
	if (ret > 0) {
		reply = t_strdup_printf("%c%s\n",
					DICT_PROTOCOL_REPLY_OK, value);
		o_stream_send_str(conn->output, reply);
	} else {
		reply = t_strdup_printf("%c\n", ret == 0 ?
					DICT_PROTOCOL_REPLY_NOTFOUND :
					DICT_PROTOCOL_REPLY_FAIL);
		o_stream_send_str(conn->output, reply);
	}
	return 0;
}

static int cmd_iterate(struct dict_client_connection *conn, const char *line)
{
	struct dict_iterate_context *ctx;
	const char *const *args;
	const char *reply, *key, *value;
	int ret;

	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 2) {
		i_error("dict client: ITERATE: broken input");
		return -1;
	}

	/* <flags> <path> */
	o_stream_cork(conn->output);
	ctx = dict_iterate_init(conn->dict, args[1], atoi(args[0]));
	while ((ret = dict_iterate(ctx, &key, &value)) > 0) {
		/* FIXME: we don't want to keep blocking here. set a flush
		   function and send the replies there when buffer gets full */
		t_push();
		reply = t_strdup_printf("%s\t%s\n", key, value);
		o_stream_send_str(conn->output, reply);
		t_pop();
	}
	dict_iterate_deinit(ctx);

	o_stream_send_str(conn->output, "\n");
	o_stream_uncork(conn->output);
	return 0;
}

static struct dict_server_transaction *
dict_server_transaction_lookup(struct dict_client_connection *conn,
			       unsigned int id)
{
	struct dict_server_transaction *transactions;
	unsigned int i, count;

	if (!array_is_created(&conn->transactions))
		return NULL;

	transactions = array_get_modifiable(&conn->transactions, &count);
	for (i = 0; i < count; i++) {
		if (transactions[i].id == id)
			return &transactions[i];
	}
	return NULL;
}

static void
dict_server_transaction_array_remove(struct dict_client_connection *conn,
				     struct dict_server_transaction *trans)
{
	const struct dict_server_transaction *transactions;
	unsigned int i, count;

	transactions = array_get(&conn->transactions, &count);
	for (i = 0; i < count; i++) {
		if (&transactions[i] == trans) {
			array_delete(&conn->transactions, i, 1);
			break;
		}
	}
}

static int cmd_begin(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	unsigned int id;

	if (!is_numeric(line, '\0')) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}

	id = (unsigned int)strtoul(line, NULL, 10);
	if (dict_server_transaction_lookup(conn, id) != NULL) {
		i_error("dict client: Transaction ID %u already exists", id);
		return -1;
	}

	if (!array_is_created(&conn->transactions))
		i_array_init(&conn->transactions, 4);

	/* <id> */
	trans = array_append_space(&conn->transactions);
	trans->id = id;
	trans->ctx = dict_transaction_begin(conn->dict);
	return 0;
}

static int
dict_server_transaction_lookup_parse(struct dict_client_connection *conn,
				     const char *line,
				     struct dict_server_transaction **trans_r)
{
	unsigned int id;

	if (!is_numeric(line, '\0')) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}

	id = (unsigned int)strtoul(line, NULL, 10);
	*trans_r = dict_server_transaction_lookup(conn, id);
	if (*trans_r == NULL) {
		i_error("dict client: Transaction ID %u doesn't exist", id);
		return -1;
	}
	return 0;
}

static int cmd_commit(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *reply;
	int ret;

	if (dict_server_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	ret = dict_transaction_commit(trans->ctx);
	reply = t_strdup_printf("%c\n", ret == 0 ? DICT_PROTOCOL_REPLY_OK :
				DICT_PROTOCOL_REPLY_FAIL);
	o_stream_send_str(conn->output, reply);
	dict_server_transaction_array_remove(conn, trans);
	return 0;
}

static int cmd_rollback(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;

	if (dict_server_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	dict_transaction_rollback(trans->ctx);
	dict_server_transaction_array_remove(conn, trans);
	return 0;
}

static int cmd_set(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *const *args;

	/* <id> <key> <value> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 3) {
		i_error("dict client: SET: broken input");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_set(trans->ctx, args[1], args[2]);
	return 0;
}

static int cmd_unset(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *const *args;

	/* <id> <key> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 2) {
		i_error("dict client: UNSET: broken input");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_unset(trans->ctx, args[1]);
	return 0;
}

static int cmd_atomic_inc(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *const *args;
	long long arg;

	/* <id> <key> <diff> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 3) {
		i_error("dict client: ATOMIC_INC: broken input");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

	if (*args[2] != '-')
		arg = (long long)strtoull(args[2], NULL, 10);
	else
		arg = -(long long)strtoull(args[2]+1, NULL, 10);
        dict_atomic_inc(trans->ctx, args[1], arg);
	return 0;
}

static struct dict_client_cmd cmds[] = {
	{ DICT_PROTOCOL_CMD_LOOKUP, cmd_lookup },
	{ DICT_PROTOCOL_CMD_ITERATE, cmd_iterate },
	{ DICT_PROTOCOL_CMD_BEGIN, cmd_begin },
	{ DICT_PROTOCOL_CMD_COMMIT, cmd_commit },
	{ DICT_PROTOCOL_CMD_ROLLBACK, cmd_rollback },
	{ DICT_PROTOCOL_CMD_SET, cmd_set },
	{ DICT_PROTOCOL_CMD_UNSET, cmd_unset },
	{ DICT_PROTOCOL_CMD_ATOMIC_INC, cmd_atomic_inc },

	{ 0, NULL }
};

static int dict_client_parse_handshake(struct dict_client_connection *conn,
				       const char *line)
{
	const char *username, *name, *value_type;

	if (*line++ != DICT_PROTOCOL_CMD_HELLO)
		return -1;

	/* check major version */
	if (*line++ - '0' != DICT_CLIENT_PROTOCOL_MAJOR_VERSION ||
	    *line++ != '\t')
		return -1;

	/* skip minor version */
	while (*line != '\t' && *line != '\0') line++;

	if (*line++ != '\t')
		return -1;

	/* get value type */
	value_type = line;
	while (*line != '\t' && *line != '\0') line++;

	if (*line++ != '\t')
		return -1;
	conn->value_type = atoi(t_strdup_until(value_type, line - 1));

	/* get username */
	username = line;
	while (*line != '\t' && *line != '\0') line++;

	if (*line++ != '\t')
		return -1;
	conn->username = i_strdup_until(username, line - 1);

	/* the rest is dict name. since we're looking it with getenv(),
	   disallow all funny characters that might confuse it, just in case. */
	name = line;
	while (*line > ' ' && *line != '=') line++;

	if (*line != '\0')
		return -1;

	conn->name = i_strdup(name);
	return 0;
}

static int dict_client_dict_init(struct dict_client_connection *conn)
{
	const char *uri;

	uri = getenv(t_strconcat("DICT_", conn->name, NULL));
	if (uri == NULL) {
		i_error("dict client: Unconfigured dictionary name '%s'",
			conn->name);
		return -1;
	}

	conn->dict = dict_init(uri, conn->value_type, conn->username);
	if (conn->dict == NULL) {
		/* dictionary initialization failed */
		i_error("Failed to initialize dictionary '%s'", conn->name);
		return -1;
	}
	return 0;
}

static void dict_client_connection_input(struct dict_client_connection *conn)
{
	const char *line;
	unsigned int i;
	int ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		dict_client_connection_deinit(conn);
		return;
	case -2:
		/* buffer full */
		i_error("dict client: Sent us more than %d bytes",
			(int)DICT_CLIENT_MAX_LINE_LENGTH);
		dict_client_connection_deinit(conn);
		return;
	}

	if (conn->username == NULL) {
		/* handshake not received yet */
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (dict_client_parse_handshake(conn, line) < 0) {
			i_error("dict client: Broken handshake");
			dict_client_connection_deinit(conn);
			return;
		}
		if (dict_client_dict_init(conn)) {
			dict_client_connection_deinit(conn);
			return;
		}
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		ret = 0;
		for (i = 0; cmds[i].cmd != '\0'; i++) {
			if (cmds[i].cmd == *line) {
				t_push();
				ret = cmds[i].func(conn, line + 1);
				t_pop();
				break;
			}
		}
		if (ret < 0) {
			dict_client_connection_deinit(conn);
			break;
		}
	}
}

static void dict_client_connection_deinit(struct dict_client_connection *conn)
{
	const struct dict_server_transaction *transactions;
	unsigned int i, count;

	if (array_is_created(&conn->transactions)) {
		transactions = array_get(&conn->transactions, &count);
		for (i = 0; i < count; i++)
			dict_transaction_rollback(transactions[i].ctx);
		array_free(&conn->transactions);
	}

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(dict client) failed: %m");

	if (conn->dict != NULL)
		dict_deinit(&conn->dict);
	i_free(conn->name);
	i_free(conn->username);
	i_free(conn);
}

static struct dict_client_connection *
dict_client_connection_init(struct dict_server *server, int fd)
{
	struct dict_client_connection *conn;

	conn = i_new(struct dict_client_connection, 1);
	conn->server = server;
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, DICT_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, 128*1024, FALSE);
	conn->io = io_add(fd, IO_READ, dict_client_connection_input, conn);
	return conn;
}

static void dict_server_listener_accept(struct dict_server *server)
{
	int fd;

	fd = net_accept(server->fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept(%s) failed: %m", server->path);
	} else {
		net_set_nonblock(fd, TRUE);
		dict_client_connection_init(server, fd);
	}
}

struct dict_server *dict_server_init(const char *path, int fd)
{
	struct dict_server *server;
	int i= 0;

	server = i_new(struct dict_server, 1);
	server->path = i_strdup(path);
	server->fd = fd;

	while (server->fd == -1) {
		server->fd = net_listen_unix(path, 64);
		if (server->fd != -1)
			break;

		if (errno != EADDRINUSE || ++i == 2)
			i_fatal("net_listen_unix(%s) failed: %m", path);

		/* see if it really exists */
		if (net_connect_unix(path) != -1 || errno != ECONNREFUSED)
			i_fatal("Socket already exists: %s", path);

		/* delete and try again */
		if (unlink(path) < 0)
			i_fatal("unlink(%s) failed: %m", path);
	}

	server->io = io_add(server->fd, IO_READ,
			    dict_server_listener_accept, server);
	return server;
}

void dict_server_deinit(struct dict_server *server)
{
	io_remove(&server->io);
	if (close(server->fd) < 0)
		i_error("close(%s) failed: %m", server->path);
	i_free(server->path);
	i_free(server);
}
