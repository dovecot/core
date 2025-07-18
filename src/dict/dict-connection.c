/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "strescape.h"
#include "settings.h"
#include "master-service.h"
#include "dict-client.h"
#include "dict-settings.h"
#include "dict-commands.h"
#include "dict-connection.h"
#include "dict-init-cache.h"

#include <unistd.h>

#define DICT_CONN_MAX_PENDING_COMMANDS 1000

static int dict_connection_dict_init(struct dict_connection *conn);
static void dict_connection_destroy(struct connection *_conn);
struct connection_list *dict_connections = NULL;

static int dict_connection_handshake_args(struct connection *_conn,
					  const char *const *args)
{
	unsigned int major;
	struct dict_connection *conn =
		container_of(_conn, struct dict_connection, conn);

	/* protocol handshake is:
	   'H' major <tab> minor <tab> 0 <tab> <tab> dict_name */
	if (str_array_length(args) < 5 || **args != 'H')
		return -1;

	/* check major version which comes right after 'H' in the
	   first parameter, store minor version. */
	if (str_to_uint(args[0]+1, &major) < 0 ||
	    str_to_uint(args[1], &conn->conn.minor_version) < 0 ||
	    major != DICT_CLIENT_PROTOCOL_MAJOR_VERSION)
		return -1;

	conn->name = i_strdup(args[4]);

	/* try initialize the given dict */
	if (dict_connection_dict_init(conn) < 0)
		return -1;

	return 1;
}

static int dict_connection_handshake_line(struct connection *conn,
					  const char *line)
{
	const char *const *args = t_strsplit_tabescaped(line);
	return dict_connection_handshake_args(conn, args);
}

static int dict_connection_dict_init_name(struct dict_connection *conn)
{
	struct event *event;
	const char *error;

	event_set_append_log_prefix(conn->conn.event,
				    t_strdup_printf("%s: ", conn->name));

	/* The dict is persistently cached, so don't use connection's event. */
	event = event_create(master_service_get_event(master_service));
	event_set_append_log_prefix(event, t_strdup_printf("%s: ", conn->name));
	event_add_str(event, "dict_name", conn->name);

	if (dict_init_cache_get(event, conn->name, &conn->dict, &error) < 0) {
		e_error(conn->conn.event, "Failed to initialize dictionary '%s': %s",
			conn->name, error);
		event_unref(&event);
		return -1;
	}
	event_unref(&event);
	return 0;
}

static int dict_connection_dict_init(struct dict_connection *conn)
{
	int ret = 0;

	if (array_is_created(&dict_settings->dicts)) {
		const char *dict_name;
		array_foreach_elem(&dict_settings->dicts, dict_name) {
			if (strcmp(conn->name, dict_name) == 0) {
				if (dict_connection_dict_init_name(conn) < 0)
					return -1;
				ret = 1;
				break;
			}
		}
	}

	if (ret == 0) {
		e_error(conn->conn.event, "Unconfigured dictionary name '%s'",
			conn->name);
		return -1;
	}
	return 0;
}

static int dict_connection_output(struct connection *_conn)
{
	struct dict_connection *conn = container_of(_conn, struct dict_connection, conn);
	int ret;

	if ((ret = o_stream_flush(conn->conn.output)) < 0) {
		dict_connection_destroy(&conn->conn);
		return 1;
	}
	if (ret > 0)
		dict_connection_cmds_output_more(conn);
	return ret;
}

struct dict_connection *
dict_connection_create(struct master_service_connection *master_conn)
{
	struct dict_connection *conn;

	conn = i_new(struct dict_connection, 1);
	conn->refcount = 1;

	connection_init_server(dict_connections, &conn->conn, master_conn->name,
			       master_conn->fd, master_conn->fd);
	event_add_category(conn->conn.event, &dict_server_event_category);

	o_stream_set_flush_callback(conn->conn.output, dict_connection_output,
				    &conn->conn);

	i_array_init(&conn->cmds, DICT_CONN_MAX_PENDING_COMMANDS);

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
	   rolled back yet. close those before dict is deinitialized. */
	if (array_is_created(&conn->transactions)) {
		array_foreach_modifiable(&conn->transactions, transaction)
			dict_transaction_rollback(&transaction->ctx);
	}

	if (conn->dict != NULL)
		dict_init_cache_unref(&conn->dict);

	if (array_is_created(&conn->transactions))
		array_free(&conn->transactions);

	array_free(&conn->cmds);

	connection_deinit(&conn->conn);

	i_free(conn->name);
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
	return FALSE;
}

static int dict_connection_input_line(struct connection *_conn, const char *line)
{
	struct dict_connection *conn =
		container_of(_conn, struct dict_connection, conn);

	i_assert(conn->dict != NULL);

	if (dict_command_input(conn, line) < 0)
		return -1;

	if (array_count(&conn->cmds) >= DICT_CONN_MAX_PENDING_COMMANDS) {
		connection_input_halt(_conn);
		return 0;
	}

	return 1;
}

static void dict_connection_unref_safe_callback(struct dict_connection *conn)
{
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

static void dict_connection_destroy(struct connection *_conn)
{
	struct dict_connection *conn = container_of(_conn, struct dict_connection, conn);

	/* If there are commands still running, we delay disconnecting can may
	   come back here. Track this so we unreference the connection only
	   once. */
	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	/* the connection is closed, but there may still be commands left
	   running. finish them, even if the calling client can't be notified
	   about whether they succeeded (clients may not even care).

	   flush the command output here in case we were waiting on iteration
	   output. */
	i_stream_close(conn->conn.input);
	o_stream_close(conn->conn.output);
	dict_connection_cmds_output_more(conn);

	io_remove(&conn->conn.io);
	dict_connection_unref(conn);
}

unsigned int dict_connections_current_count(void)
{
	return dict_connections->connections_count;
}

void dict_connections_destroy_all(void)
{
	connection_list_deinit(&dict_connections);
}

static struct connection_settings dict_connections_set = {
	.dont_send_version = TRUE,
	.input_max_size = DICT_CLIENT_MAX_LINE_LENGTH,
	.output_max_size = 128*1024,
};

static struct connection_vfuncs dict_connections_vfuncs = {
	.destroy = dict_connection_destroy,
	.handshake_line = dict_connection_handshake_line,
	.input_line = dict_connection_input_line,
};

void dict_connections_init(void)
{
	dict_connections = connection_list_init(&dict_connections_set,
						&dict_connections_vfuncs);
}
