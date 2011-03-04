/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "master-service.h"
#include "dict-client.h"
#include "dict-settings.h"
#include "dict-commands.h"
#include "dict-connection.h"

#include <stdlib.h>
#include <unistd.h>

static struct dict_connection *dict_connections;

static int dict_connection_parse_handshake(struct dict_connection *conn,
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

static int dict_connection_dict_init(struct dict_connection *conn)
{
	const char *const *strlist;
	unsigned int i, count;
	const char *uri;

	strlist = array_get(&dict_settings->dicts, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(strlist[i], conn->name) == 0)
			break;
	}

	if (i == count) {
		i_error("dict client: Unconfigured dictionary name '%s'",
			conn->name);
		return -1;
	}
	uri = strlist[i+1];

	conn->dict = dict_init(uri, conn->value_type, conn->username,
			       dict_settings->base_dir);
	if (conn->dict == NULL) {
		/* dictionary initialization failed */
		i_error("Failed to initialize dictionary '%s'", conn->name);
		return -1;
	}
	return 0;
}

static void dict_connection_input(struct dict_connection *conn)
{
	const char *line;
	int ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		dict_connection_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("dict client: Sent us more than %d bytes",
			(int)DICT_CLIENT_MAX_LINE_LENGTH);
		dict_connection_destroy(conn);
		return;
	}

	if (conn->username == NULL) {
		/* handshake not received yet */
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (dict_connection_parse_handshake(conn, line) < 0) {
			i_error("dict client: Broken handshake");
			dict_connection_destroy(conn);
			return;
		}
		if (dict_connection_dict_init(conn)) {
			dict_connection_destroy(conn);
			return;
		}
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = dict_command_input(conn, line);
		} T_END;
		if (ret < 0) {
			dict_connection_destroy(conn);
			break;
		}
	}
}

struct dict_connection *dict_connection_create(int fd)
{
	struct dict_connection *conn;

	conn = i_new(struct dict_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, DICT_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, 128*1024, FALSE);
	conn->io = io_add(fd, IO_READ, dict_connection_input, conn);
	DLLIST_PREPEND(&dict_connections, conn);
	return conn;
}

void dict_connection_destroy(struct dict_connection *conn)
{
	struct dict_connection_transaction *transaction;

	DLLIST_REMOVE(&dict_connections, conn);

	if (array_is_created(&conn->transactions)) {
		array_foreach_modifiable(&conn->transactions, transaction)
			dict_transaction_rollback(&transaction->ctx);
		array_free(&conn->transactions);
	}

	if (conn->iter_ctx != NULL)
		(void)dict_iterate_deinit(&conn->iter_ctx);

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

	master_service_client_connection_destroyed(master_service);
}

void dict_connections_destroy_all(void)
{
	while (dict_connections != NULL)
		dict_connection_destroy(dict_connections);
}
