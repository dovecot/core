/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "settings-parser.h"
#include "doveadm-print.h"
#include "doveadm-util.h"
#include "doveadm-server.h"
#include "doveadm-settings.h"
#include "server-connection.h"

#include <sysexits.h>
#include <unistd.h>

#define MAX_INBUF_SIZE (1024*32)

enum server_reply_state {
	SERVER_REPLY_STATE_DONE = 0,
	SERVER_REPLY_STATE_PRINT,
	SERVER_REPLY_STATE_RET
};

struct server_connection {
	struct doveadm_server *server;

	pool_t pool;
	struct doveadm_settings *set;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct ssl_iostream *ssl_iostream;

	const char *delayed_cmd;
	server_cmd_callback_t *callback;
	void *context;

	enum server_reply_state state;

	unsigned int handshaked:1;
	unsigned int authenticated:1;
	unsigned int streaming:1;
};

static struct server_connection *printing_conn = NULL;

static void server_connection_input(struct server_connection *conn);

static void print_connection_released(void)
{
	struct doveadm_server *server = printing_conn->server;
	struct server_connection *const *conns;
	unsigned int i, count;

	printing_conn = NULL;

	conns = array_get(&server->connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i]->io != NULL)
			continue;

		conns[i]->io = io_add(conns[i]->fd, IO_READ,
				      server_connection_input, conns[i]);
		server_connection_input(conns[i]);
		if (printing_conn != NULL)
			break;
	}
}

static void
server_connection_callback(struct server_connection *conn, int exit_code)
{
	server_cmd_callback_t *callback = conn->callback;

	conn->callback = NULL;
	callback(exit_code, conn->context);
}

static void stream_data(string_t *str, const unsigned char *data, size_t size)
{
	const char *text;

	str_truncate(str, 0);
	str_append_n(str, data, size);
	text = str_tabunescape(str_c_modifiable(str));
	doveadm_print_stream(text, strlen(text));
}

static void server_flush_field(struct server_connection *conn, string_t *str,
			       const unsigned char *data, size_t size)
{
	if (conn->streaming) {
		conn->streaming = FALSE;
		if (size > 0)
			stream_data(str, data, size);
		doveadm_print_stream("", 0);
	} else {
		const char *text;

		str_truncate(str, 0);
		str_append_n(str, data, size);
		text = str_tabunescape(str_c_modifiable(str));
		doveadm_print(text);
	}
}

static void
server_handle_input(struct server_connection *conn,
		    const unsigned char *data, size_t size)
{
	string_t *str;
	size_t i, start;

	if (printing_conn == conn) {
		/* continue printing */
	} else if (printing_conn == NULL) {
		printing_conn = conn;
	} else {
		/* someone else is printing. don't continue until it
		   goes away */
		io_remove(&conn->io);
		return;
	}

	if (data[size-1] == '\001') {
		/* last character is an escape */
		size--;
	}

	str = t_str_new(128);
	for (i = start = 0; i < size; i++) {
		if (data[i] == '\n') {
			if (i != start) {
				i_error("doveadm server sent broken print input");
				server_connection_destroy(&conn);
				return;
			}
			conn->state = SERVER_REPLY_STATE_RET;
			i_stream_skip(conn->input, i + 1);

			print_connection_released();
			return;
		}
		if (data[i] == '\t') {
			server_flush_field(conn, str, data + start, i - start);
			start = i + 1;
		}
	}
	if (start != size) {
		conn->streaming = TRUE;
		stream_data(str, data + start, size - start);
	}
	i_stream_skip(conn->input, size);
}

static void server_connection_authenticated(struct server_connection *conn)
{
	conn->authenticated = TRUE;
	if (conn->delayed_cmd != NULL) {
		o_stream_nsend_str(conn->output, conn->delayed_cmd);
		conn->delayed_cmd = NULL;
	}
}

static int
server_connection_authenticate(struct server_connection *conn)
{
	string_t *plain = t_str_new(128);
	string_t *cmd = t_str_new(128);

	if (*conn->set->doveadm_password == '\0') {
		i_error("doveadm_password not set, "
			"can't authenticate to remote server");
		return -1;
	}

	str_append_c(plain, '\0');
	str_append(plain, "doveadm");
	str_append_c(plain, '\0');
	str_append(plain, conn->set->doveadm_password);

	str_append(cmd, "PLAIN\t");
	base64_encode(plain->data, plain->used, cmd);
	str_append_c(cmd, '\n');

	o_stream_nsend(conn->output, cmd->data, cmd->used);
	return 0;
}

static void server_connection_input(struct server_connection *conn)
{
	const unsigned char *data;
	size_t size;
	const char *line;
	int exit_code;

	if (!conn->handshaked) {
		if ((line = i_stream_read_next_line(conn->input)) == NULL) {
			if (conn->input->eof || conn->input->stream_errno != 0)
				server_connection_destroy(&conn);
			return;
		}

		conn->handshaked = TRUE;
		if (strcmp(line, "+") == 0)
			server_connection_authenticated(conn);
		else if (strcmp(line, "-") == 0) {
			if (server_connection_authenticate(conn) < 0) {
				server_connection_destroy(&conn);
				return;
			}
			return;
		} else {
			i_error("doveadm server sent invalid handshake: %s",
				line);
			server_connection_destroy(&conn);
			return;
		}
	}

	if (i_stream_read(conn->input) < 0) {
		/* disconnected */
		server_connection_destroy(&conn);
		return;
	}

	if (!conn->authenticated) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;
		if (strcmp(line, "+") == 0)
			server_connection_authenticated(conn);
		else {
			i_error("doveadm authentication failed (%s)", line+1);
			server_connection_destroy(&conn);
			return;
		}
	}

	data = i_stream_get_data(conn->input, &size);
	if (size == 0)
		return;

	switch (conn->state) {
	case SERVER_REPLY_STATE_DONE:
		i_error("doveadm server sent unexpected input");
		server_connection_destroy(&conn);
		return;
	case SERVER_REPLY_STATE_PRINT:
		server_handle_input(conn, data, size);
		if (conn->state != SERVER_REPLY_STATE_RET)
			break;
		/* fall through */
	case SERVER_REPLY_STATE_RET:
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;
		if (line[0] == '+')
			server_connection_callback(conn, 0);
		else if (line[0] == '-') {
			line++;
			if (strcmp(line, "NOUSER") == 0)
				exit_code = EX_NOUSER;
			else if (str_to_int(line, &exit_code) < 0) {
				/* old doveadm-server */
				exit_code = EX_TEMPFAIL;
			}
			server_connection_callback(conn, exit_code);
		} else {
			i_error("doveadm server sent broken input "
				"(expected cmd reply): %s", line);
			server_connection_destroy(&conn);
			break;
		}
		if (conn->callback == NULL) {
			/* we're finished, close the connection */
			server_connection_destroy(&conn);
		}
		break;
	}
}

static int server_connection_read_settings(struct server_connection *conn)
{
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;
	unsigned int port;
	void *set;

	memset(&input, 0, sizeof(input));
	input.roots = set_roots;
	input.service = "doveadm";

	(void)net_getsockname(conn->fd, &input.local_ip, &port);
	(void)net_getpeername(conn->fd, &input.remote_ip, &port);

	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0) {
		i_error("Error reading configuration: %s", error);
		return -1;
	}
	set = master_service_settings_get_others(master_service)[0];
	conn->set = settings_dup(&doveadm_setting_parser_info, set, conn->pool);
	return 0;
}

static int server_connection_ssl_handshaked(const char **error_r, void *context)
{
	struct server_connection *conn = context;
	const char *host, *p;

	host = conn->server->name;
	p = strrchr(host, ':');
	if (p != NULL)
		host = t_strdup_until(host, p);

	if (ssl_iostream_check_cert_validity(conn->ssl_iostream, host, error_r) < 0)
		return -1;
	if (doveadm_debug)
		i_debug("%s: SSL handshake successful", conn->server->name);
	return 0;
}

static int server_connection_init_ssl(struct server_connection *conn)
{
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (conn->server->ssl_ctx == NULL)
		return 0;

	memset(&ssl_set, 0, sizeof(ssl_set));
	ssl_set.verify_remote_cert = TRUE;
	ssl_set.require_valid_cert = TRUE;
	ssl_set.verbose_invalid_cert = TRUE;

	if (io_stream_create_ssl_client(conn->server->ssl_ctx,
					conn->server->name, &ssl_set,
					&conn->input, &conn->output,
					&conn->ssl_iostream, &error) < 0) {
		i_error("Couldn't initialize SSL client: %s", error);
		return -1;
	}
	ssl_iostream_set_handshake_callback(conn->ssl_iostream,
					    server_connection_ssl_handshaked,
					    conn);
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		i_error("SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}
	return 0;
}

int server_connection_create(struct doveadm_server *server,
			     struct server_connection **conn_r)
{
#define DOVEADM_SERVER_HANDSHAKE "VERSION\tdoveadm-server\t1\t0\n"
	struct server_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("doveadm server connection", 1024*16);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;
	conn->server = server;
	conn->fd = doveadm_connect_with_default_port(server->name,
						     doveadm_settings->doveadm_port);
	net_set_nonblock(conn->fd, TRUE);
	conn->io = io_add(conn->fd, IO_READ, server_connection_input, conn);
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);

	array_append(&conn->server->connections, &conn, 1);

	if (server_connection_read_settings(conn) < 0 ||
	    server_connection_init_ssl(conn) < 0) {
		server_connection_destroy(&conn);
		return -1;
	}

	o_stream_set_no_error_handling(conn->output, TRUE);
	conn->state = SERVER_REPLY_STATE_DONE;
	o_stream_nsend_str(conn->output, DOVEADM_SERVER_HANDSHAKE);

	*conn_r = conn;
	return 0;
}

void server_connection_destroy(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;
	struct server_connection *const *conns;
	unsigned int i, count;

	*_conn = NULL;

	conns = array_get(&conn->server->connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i] == conn) {
			array_delete(&conn->server->connections, i, 1);
			break;
		}
	}

	if (conn->callback != NULL)
		server_connection_callback(conn, SERVER_EXIT_CODE_DISCONNECTED);
	if (printing_conn == conn)
		print_connection_released();

	if (conn->input != NULL)
		i_stream_destroy(&conn->input);
	if (conn->output != NULL)
		o_stream_destroy(&conn->output);
	if (conn->ssl_iostream != NULL)
		ssl_iostream_unref(&conn->ssl_iostream);
	if (conn->io != NULL)
		io_remove(&conn->io);
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_error("close(server) failed: %m");
	}
	pool_unref(&conn->pool);
}

struct doveadm_server *
server_connection_get_server(struct server_connection *conn)
{
	return conn->server;
}

void server_connection_cmd(struct server_connection *conn, const char *line,
			   server_cmd_callback_t *callback, void *context)
{
	i_assert(conn->delayed_cmd == NULL);

	conn->state = SERVER_REPLY_STATE_PRINT;
	if (conn->authenticated)
		o_stream_nsend_str(conn->output, line);
	else
		conn->delayed_cmd = p_strdup(conn->pool, line);
	conn->callback = callback;
	conn->context = context;
}

bool server_connection_is_idle(struct server_connection *conn)
{
	return conn->callback == NULL;
}

void server_connection_extract(struct server_connection *conn,
			       struct istream **istream_r,
			       struct ostream **ostream_r,
			       struct ssl_iostream **ssl_iostream_r)
{
	*istream_r = conn->input;
	*ostream_r = conn->output;
	*ssl_iostream_r = conn->ssl_iostream;

	conn->input = NULL;
	conn->output = NULL;
	conn->ssl_iostream = NULL;
	if (conn->io != NULL)
		io_remove(&conn->io);
	conn->fd = -1;
}
