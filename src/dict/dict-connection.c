/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

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

#include <unistd.h>

#define DICT_CONN_MAX_PENDING_COMMANDS 5

static struct dict_connection *dict_connections;
static unsigned int dict_connections_count = 0;

static int dict_connection_parse_handshake(struct dict_connection *conn,
					   const char *line)
{
	const char *username, *name, *value_type;
	unsigned int value_type_num;

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
	if (str_to_uint(t_strdup_until(value_type, line - 1), &value_type_num) < 0)
		return -1;
	if (value_type_num >= DICT_DATA_TYPE_LAST)
		return -1;
	conn->value_type = (enum dict_data_type)value_type_num;

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
	const char *uri, *error;

	if (!array_is_created(&dict_settings->dicts)) {
		i_error("dict client: No dictionaries configured");
		return -1;
	}
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

	if (dict_init(uri, conn->value_type, conn->username,
		      dict_settings->base_dir, &conn->dict, &error) < 0) {
		/* dictionary initialization failed */
		i_error("Failed to initialize dictionary '%s': %s",
			conn->name, error);
		return -1;
	}
	return 0;
}

static void dict_connection_input(struct dict_connection *conn)
{
	const char *line;
	int ret;

	if (conn->to_input != NULL)
		timeout_remove(&conn->to_input);

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
		if (array_count(&conn->cmds) >= DICT_CONN_MAX_PENDING_COMMANDS) {
			io_remove(&conn->io);
			if (conn->to_input != NULL)
				timeout_remove(&conn->to_input);
			break;
		}
	}
}

void dict_connection_continue_input(struct dict_connection *conn)
{
	if (conn->io != NULL || conn->destroyed)
		return;

	conn->io = io_add(conn->fd, IO_READ, dict_connection_input, conn);
	if (conn->to_input == NULL)
		conn->to_input = timeout_add_short(0, dict_connection_input, conn);
}

static int dict_connection_output(struct dict_connection *conn)
{
	int ret;

	if ((ret = o_stream_flush(conn->output)) < 0) {
		dict_connection_destroy(conn);
		return 1;
	}
	if (ret > 0)
		dict_connection_cmds_output_more(conn);
	return ret;
}

struct dict_connection *dict_connection_create(int fd)
{
	struct dict_connection *conn;

	conn = i_new(struct dict_connection, 1);
	conn->refcount = 1;
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, DICT_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, 128*1024, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_set_flush_callback(conn->output, dict_connection_output, conn);
	conn->io = io_add(fd, IO_READ, dict_connection_input, conn);
	i_array_init(&conn->cmds, DICT_CONN_MAX_PENDING_COMMANDS);

	dict_connections_count++;
	DLLIST_PREPEND(&dict_connections, conn);
	return conn;
}

void dict_connection_ref(struct dict_connection *conn)
{
	i_assert(conn->refcount > 0);
	conn->refcount++;
}

bool dict_connection_unref(struct dict_connection *conn)
{
	struct dict_connection_transaction *transaction;

	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return TRUE;

	i_assert(array_count(&conn->cmds) == 0);

	/* we should have only transactions that haven't been committed or
	   rollbacked yet. close those before dict is deinitialized. */
	if (array_is_created(&conn->transactions)) {
		array_foreach_modifiable(&conn->transactions, transaction) {
			if (transaction->ctx != NULL)
				dict_transaction_rollback(&transaction->ctx);
		}
	}

	if (conn->dict != NULL)
		dict_deinit(&conn->dict);

	if (array_is_created(&conn->transactions))
		array_free(&conn->transactions);

	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);

	array_free(&conn->cmds);
	i_free(conn->name);
	i_free(conn->username);
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
	return FALSE;
}

static void dict_connection_unref_safe_callback(struct dict_connection *conn)
{
	if (conn->to_unref != NULL)
		timeout_remove(&conn->to_unref);
	(void)dict_connection_unref(conn);
}

void dict_connection_unref_safe(struct dict_connection *conn)
{
	if (conn->refcount == 1) {
		/* delayed unref to make sure we don't try to call
		   dict_deinit() from a dict-callback. that's too much trouble
		   for each dict driver to be able to handle. */
		if (conn->to_unref == NULL) {
			conn->to_unref = timeout_add_short(0,
				dict_connection_unref_safe_callback, conn);
		}
	} else {
		(void)dict_connection_unref(conn);
	}
}

void dict_connection_destroy(struct dict_connection *conn)
{
	i_assert(!conn->destroyed);
	i_assert(conn->to_unref == NULL);

	i_assert(dict_connections_count > 0);
	dict_connections_count--;

	conn->destroyed = TRUE;
	DLLIST_REMOVE(&dict_connections, conn);

	if (conn->to_input != NULL)
		timeout_remove(&conn->to_input);
	if (conn->io != NULL)
		io_remove(&conn->io);
	i_stream_close(conn->input);
	o_stream_close(conn->output);
	if (close(conn->fd) < 0)
		i_error("close(dict client) failed: %m");
	conn->fd = -1;

	/* the connection is closed, but there may still be commands left
	   running. finish them, even if the calling client can't be notified
	   about whether they succeeded (clients may not even care).

	   flush the command output here in case we were waiting on iteration
	   output. */
	dict_connection_cmds_output_more(conn);

	dict_connection_unref(conn);
}

unsigned int dict_connections_current_count(void)
{
	return dict_connections_count;
}

void dict_connections_destroy_all(void)
{
	while (dict_connections != NULL)
		dict_connection_destroy(dict_connections);
}
