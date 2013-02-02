/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "master-service.h"
#include "userdb.h"
#include "auth-postfix-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024*50)

struct auth_postfix_connection {
	struct auth_postfix_connection *prev, *next;
	struct auth *auth;
	int refcount;

	int fd;
	char *path;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int destroyed:1;
};

static void postfix_input(struct auth_postfix_connection *conn);
static void auth_postfix_connection_ref(struct auth_postfix_connection *conn);
static void auth_postfix_connection_destroy(struct auth_postfix_connection **_conn);
static void auth_postfix_connection_unref(struct auth_postfix_connection **_conn);

static struct auth_postfix_connection *auth_postfix_connections;

static int
postfix_input_auth_request(struct auth_postfix_connection *conn,
			   const char *username,
			   struct auth_request **request_r, const char **error_r)
{
	struct auth_request *auth_request;

	auth_request = auth_request_new_dummy();
	auth_request->id = 1;
	auth_request->context = conn;
	auth_postfix_connection_ref(conn);

	if (!auth_request_set_username(auth_request, username, error_r)) {
		*request_r = auth_request;
		return FALSE;
	}
	(void)auth_request_import_info(auth_request, "service", "postfix");

	auth_request_init(auth_request);
	*request_r = auth_request;
	return TRUE;
}

static void
user_callback(enum userdb_result result, struct auth_request *auth_request)
{
	struct auth_postfix_connection *conn = auth_request->context;
	string_t *str;
	const char *value;

	if (auth_request->userdb_lookup_failed)
		result = USERDB_RESULT_INTERNAL_FAILURE;

	str = t_str_new(128);
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		if (auth_request->userdb_lookup_failed)
			value = auth_fields_find(auth_request->userdb_reply, "reason");
		else
			value = NULL;
		str_printfa(str, "400 %s",
			    value != NULL ? value: "Internal failure");
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_append(str, "500 User not found");
		break;
	case USERDB_RESULT_OK:
		str_append(str, "200 1");
		break;
	}

	if (conn->auth->set->debug)
		i_debug("postfix out: %s", str_c(str));

	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));

	i_assert(conn->io == NULL);
	if (!conn->destroyed)
		conn->io = io_add(conn->fd, IO_READ, postfix_input, conn);

	auth_request_unref(&auth_request);
	auth_postfix_connection_unref(&conn);
}

static bool
postfix_input_user(struct auth_postfix_connection *conn, const char *username)
{
	struct auth_request *auth_request;
	const char *error;

	io_remove(&conn->io);
	if (!postfix_input_auth_request(conn, username,
					&auth_request, &error)) {
		auth_request_log_info(auth_request, "postfix", "%s", error);
		user_callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
	} else {
		auth_request_set_state(auth_request, AUTH_REQUEST_STATE_USERDB);
		auth_request_lookup_user(auth_request, user_callback);
	}
	return TRUE;
}

static bool
auth_postfix_input_line(struct auth_postfix_connection *conn, const char *line)
{
	if (conn->auth->set->debug)
		i_debug("postfix in: %s", line);

	if (strncasecmp(line, "get ", 4) == 0)
		return postfix_input_user(conn, line + 4);

	i_error("BUG: Unknown command in postfix socket: %s",
		str_sanitize(line, 80));
	return FALSE;
}

static void postfix_input(struct auth_postfix_connection *conn)
{
 	char *line;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
                auth_postfix_connection_destroy(&conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Postfix sent us more than %d bytes",
			(int)MAX_INBUF_SIZE);
                auth_postfix_connection_destroy(&conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = auth_postfix_input_line(conn, line);
		} T_END;
		if (!ret) {
			auth_postfix_connection_destroy(&conn);
			return;
		}
	}
}

struct auth_postfix_connection *
auth_postfix_connection_create(struct auth *auth, int fd)
{
	struct auth_postfix_connection *conn;

	conn = i_new(struct auth_postfix_connection, 1);
	conn->refcount = 1;
	conn->fd = fd;
	conn->auth = auth;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);
	conn->io = io_add(fd, IO_READ, postfix_input, conn);
	DLLIST_PREPEND(&auth_postfix_connections, conn);
	return conn;
}

static void
auth_postfix_connection_destroy(struct auth_postfix_connection **_conn)
{
        struct auth_postfix_connection *conn = *_conn;

	*_conn = NULL;
	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	DLLIST_REMOVE(&auth_postfix_connections, conn);

	if (conn->input != NULL)
		i_stream_close(conn->input);
	if (conn->output != NULL)
		o_stream_close(conn->output);
	if (conn->io != NULL)
		io_remove(&conn->io);
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_error("close(%s): %m", conn->path);
		conn->fd = -1;
	}

	master_service_client_connection_destroyed(master_service);
	auth_postfix_connection_unref(&conn);
}

static void auth_postfix_connection_ref(struct auth_postfix_connection *conn)
{
	i_assert(conn->refcount > 0);

	conn->refcount++;
}

static void
auth_postfix_connection_unref(struct auth_postfix_connection **_conn)
{
	struct auth_postfix_connection *conn = *_conn;

	*_conn = NULL;
	i_assert(conn->refcount > 0);

	if (--conn->refcount > 0)
		return;

	if (conn->input != NULL)
		i_stream_unref(&conn->input);
	if (conn->output != NULL)
		o_stream_unref(&conn->output);
	i_free(conn);
}

void auth_postfix_connections_destroy_all(void)
{
	struct auth_postfix_connection *conn;

	while (auth_postfix_connections != NULL) {
		conn = auth_postfix_connections;
		auth_postfix_connection_destroy(&conn);
	}
}
