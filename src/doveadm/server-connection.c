/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "istream-multiplex.h"
#include "ostream.h"
#include "ostream-dot.h"
#include "str.h"
#include "strescape.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "settings-parser.h"
#include "doveadm.h"
#include "doveadm-print.h"
#include "doveadm-util.h"
#include "doveadm-server.h"
#include "doveadm-settings.h"
#include "server-connection.h"

#include <sysexits.h>
#include <unistd.h>

#define DOVEADM_LOG_CHANNEL_ID 'L'

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
	unsigned int minor;

	struct io *io;
	struct io *io_log;
	struct istream *input;
	struct istream *log_input;
	struct ostream *output;
	struct ssl_iostream *ssl_iostream;
	struct timeout *to_input;

	struct istream *cmd_input;
	struct ostream *cmd_output;
	const char *delayed_cmd;
	server_cmd_callback_t *callback;
	void *context;

	enum server_reply_state state;

	bool version_received:1;
	bool authenticate_sent:1;
	bool authenticated:1;
	bool streaming:1;
};

static struct server_connection *printing_conn = NULL;
static ARRAY(struct doveadm_server *) print_pending_servers = ARRAY_INIT;

static void server_connection_input(struct server_connection *conn);
static bool server_connection_input_one(struct server_connection *conn);

static void server_set_print_pending(struct doveadm_server *server)
{
	struct doveadm_server *const *serverp;

	if (!array_is_created(&print_pending_servers))
		i_array_init(&print_pending_servers, 16);
	array_foreach(&print_pending_servers, serverp) {
		if (*serverp == server)
			return;
	}
	array_append(&print_pending_servers, &server, 1);
}

static void server_print_connection_released(struct doveadm_server *server)
{
	struct server_connection *const *conns;
	unsigned int i, count;

	conns = array_get(&server->connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i]->io != NULL)
			continue;

		conns[i]->io = io_add(conns[i]->fd, IO_READ,
				      server_connection_input, conns[i]);
		conns[i]->to_input = timeout_add_short(0,
			server_connection_input, conns[i]);
	}
}

static void print_connection_released(void)
{
	struct doveadm_server *const *serverp;

	printing_conn = NULL;
	if (!array_is_created(&print_pending_servers))
		return;

	array_foreach(&print_pending_servers, serverp)
		server_print_connection_released(*serverp);
	array_free(&print_pending_servers);
}

static int server_connection_send_cmd_input_more(struct server_connection *conn)
{
	enum ostream_send_istream_result res;
	int ret = -1;

	/* ostream-dot writes only up to max buffer size, so keep it non-zero */
	o_stream_set_max_buffer_size(conn->cmd_output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(conn->cmd_output, conn->cmd_input);
	o_stream_set_max_buffer_size(conn->cmd_output, (size_t)-1);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		return 1;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_error("read(%s) failed: %s",
			i_stream_get_name(conn->cmd_input),
			i_stream_get_error(conn->cmd_input));
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		i_error("write(%s) failed: %s",
			o_stream_get_name(conn->cmd_output),
			o_stream_get_error(conn->cmd_output));
		break;
	}
	if (res == OSTREAM_SEND_ISTREAM_RESULT_FINISHED) {
		if ((ret = o_stream_finish(conn->cmd_output)) == 0)
			return 0;
		else if (ret < 0) {
			i_error("write(%s) failed: %s",
				o_stream_get_name(conn->cmd_output),
				o_stream_get_error(conn->cmd_output));
		}
	}

	i_stream_destroy(&conn->cmd_input);
	o_stream_destroy(&conn->cmd_output);
	return ret;
}

static void server_connection_send_cmd_input(struct server_connection *conn)
{
	if (conn->cmd_input == NULL)
		return;

	conn->cmd_output = o_stream_create_dot(conn->output, TRUE);
	(void)server_connection_send_cmd_input_more(conn);
}

static int server_connection_output(struct server_connection *conn)
{
	int ret;

	ret = o_stream_flush(conn->output);
	if (ret > 0 && conn->cmd_input != NULL && conn->delayed_cmd == NULL)
		ret = server_connection_send_cmd_input_more(conn);
	if (ret < 0)
		server_connection_destroy(&conn);
	return ret;
}

static void
server_connection_callback(struct server_connection *conn,
			   int exit_code, const char *error)
{
	server_cmd_callback_t *callback = conn->callback;

	conn->callback = NULL;
	callback(exit_code, error, conn->context);
}

static void stream_data(string_t *str, const unsigned char *data, size_t size)
{
	str_truncate(str, 0);
	str_append_tabunescaped(str, data, size);
	doveadm_print_stream(str->data, str->used);
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
		str_truncate(str, 0);
		str_append_tabunescaped(str, data, size);
		doveadm_print(str_c(str));
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
		server_set_print_pending(conn->server);
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
		server_connection_send_cmd_input(conn);
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
	str_append(plain, conn->set->doveadm_username);
	str_append_c(plain, '\0');
	str_append(plain, conn->set->doveadm_password);

	str_append(cmd, "PLAIN\t");
	base64_encode(plain->data, plain->used, cmd);
	str_append_c(cmd, '\n');

	o_stream_nsend(conn->output, cmd->data, cmd->used);
	conn->authenticate_sent = TRUE;
	return 0;
}

static void server_log_disconnect_error(struct server_connection *conn)
{
	const char *error;

	error = conn->ssl_iostream == NULL ? NULL :
		ssl_iostream_get_last_error(conn->ssl_iostream);
	if (error == NULL) {
		error = conn->input->stream_errno == 0 ? "EOF" :
			strerror(conn->input->stream_errno);
	}
	i_error("doveadm server disconnected before handshake: %s", error);
}

static void server_connection_print_log(struct server_connection *conn)
{
	const char *line;
	struct failure_context ctx;
	i_zero(&ctx);

	while((line = i_stream_read_next_line(conn->log_input))!=NULL) {
		/* skip empty lines */
		if (*line == '\0') continue;

		if (!doveadm_log_type_from_char(line[0], &ctx.type))
			i_warning("Doveadm server sent invalid log type 0x%02x",
				  line[0]);
		line++;
		i_log_type(&ctx, "remote(%s): %s", conn->server->name, line);
	}
}

static void server_connection_start_multiplex(struct server_connection *conn)
{
	struct istream *is = conn->input;
	conn->input = i_stream_create_multiplex(is, MAX_INBUF_SIZE);
	i_stream_unref(&is);
	io_remove(&conn->io);
	conn->io = io_add_istream(conn->input, server_connection_input, conn);
	conn->log_input = i_stream_multiplex_add_channel(conn->input, DOVEADM_LOG_CHANNEL_ID);
	conn->io_log = io_add_istream(conn->log_input, server_connection_print_log, conn);
	i_stream_set_return_partial_line(conn->log_input, TRUE);
}

static void server_connection_input(struct server_connection *conn)
{
	const char *line;

	timeout_remove(&conn->to_input);

	if (i_stream_read(conn->input) < 0) {
		/* disconnected */
		server_log_disconnect_error(conn);
		server_connection_destroy(&conn);
		return;
	}

	while (!conn->authenticated) {
		if ((line = i_stream_next_line(conn->input)) == NULL) {
			if (conn->input->eof) {
				/* we'll also get here if the line is too long */
				server_log_disconnect_error(conn);
				server_connection_destroy(&conn);
			}
			return;
		}
		/* Allow VERSION before or after the "+" or "-" line,
		   because v2.2.33 sent the version after and newer
		   versions send before. */
		if (!conn->version_received &&
		    str_begins(line, "VERSION\t")) {
			if (!version_string_verify_full(line, "doveadm-client",
							DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR,
							&conn->minor)) {
				i_error("doveadm server not compatible with this client"
					"(mixed old and new binaries?)");
				server_connection_destroy(&conn);
				return;
			}
			conn->version_received = TRUE;
		} else if (strcmp(line, "+") == 0) {
			if (conn->minor > 0)
				server_connection_start_multiplex(conn);
			server_connection_authenticated(conn);
		} else if (strcmp(line, "-") == 0) {
			if (conn->authenticate_sent) {
				i_error("doveadm authentication failed (%s)",
					line+1);
				server_connection_destroy(&conn);
				return;
			}
			if (server_connection_authenticate(conn) < 0) {
				server_connection_destroy(&conn);
				return;
			}
		} else {
			i_error("doveadm server sent invalid handshake: %s",
				line);
			server_connection_destroy(&conn);
			return;
		}
	}

	while (server_connection_input_one(conn)) ;
}

static bool server_connection_input_one(struct server_connection *conn)
{
	const unsigned char *data;
	size_t size;
	const char *line;
	int exit_code;

	/* check logs - NOTE: must be before i_stream_get_data() since checking
	   for logs may add data to our channel. */
	if (conn->log_input != NULL)
		(void)server_connection_print_log(conn);

	data = i_stream_get_data(conn->input, &size);
	if (size == 0)
		return FALSE;

	switch (conn->state) {
	case SERVER_REPLY_STATE_DONE:
		i_error("doveadm server sent unexpected input");
		server_connection_destroy(&conn);
		return FALSE;
	case SERVER_REPLY_STATE_PRINT:
		server_handle_input(conn, data, size);
		if (conn->state != SERVER_REPLY_STATE_RET)
			return FALSE;
		/* fall through */
	case SERVER_REPLY_STATE_RET:
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return FALSE;
		if (line[0] == '+')
			server_connection_callback(conn, 0, "");
		else if (line[0] == '-') {
			line++;
			exit_code = doveadm_str_to_exit_code(line);
			if (exit_code == DOVEADM_EX_UNKNOWN &&
			    str_to_int(line, &exit_code) < 0) {
				/* old doveadm-server */
				exit_code = EX_TEMPFAIL;
			}
			server_connection_callback(conn, exit_code, line);
		} else {
			i_error("doveadm server sent broken input "
				"(expected cmd reply): %s", line);
			server_connection_destroy(&conn);
			return FALSE;
		}
		if (conn->callback == NULL) {
			/* we're finished, close the connection */
			server_connection_destroy(&conn);
			return FALSE;
		}
		return TRUE;
	}
	i_unreached();
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
	in_port_t port;
	void *set;

	i_zero(&input);
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

static int server_connection_init_ssl(struct server_connection *conn)
{
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (conn->server->ssl_ctx == NULL)
		return 0;

	doveadm_get_ssl_settings(&ssl_set, conn->pool);
	if (ssl_set.allow_invalid_cert)
		ssl_set.verbose_invalid_cert = TRUE;

	if (io_stream_create_ssl_client(conn->server->ssl_ctx,
					conn->server->hostname, &ssl_set,
					&conn->input, &conn->output,
					&conn->ssl_iostream, &error) < 0) {
		i_error("Couldn't initialize SSL client: %s", error);
		return -1;
	}
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
	struct server_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("doveadm server connection", 1024*16);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;
	conn->server = server;
	conn->fd = doveadm_connect_with_default_port(server->name,
						     doveadm_settings->doveadm_port);
	net_set_nonblock(conn->fd, TRUE);
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1);
	o_stream_set_flush_callback(conn->output, server_connection_output, conn);
	o_stream_set_no_error_handling(conn->output, TRUE);

	i_stream_set_name(conn->input, server->name);
	o_stream_set_name(conn->output, server->name);

	array_append(&conn->server->connections, &conn, 1);

	if (server_connection_read_settings(conn) < 0 ||
	    server_connection_init_ssl(conn) < 0) {
		server_connection_destroy(&conn);
		return -1;
	}
	conn->io = io_add_istream(conn->input, server_connection_input, conn);

	conn->state = SERVER_REPLY_STATE_DONE;
	o_stream_nsend_str(conn->output, DOVEADM_SERVER_PROTOCOL_VERSION_LINE"\n");

	*conn_r = conn;
	return 0;
}

void server_connection_destroy(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;
	struct server_connection *const *conns;
	const char *error;
	unsigned int i, count;

	*_conn = NULL;

	conns = array_get(&conn->server->connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i] == conn) {
			array_delete(&conn->server->connections, i, 1);
			break;
		}
	}

	if (conn->callback != NULL) {
		error = conn->ssl_iostream == NULL ? NULL :
			ssl_iostream_get_last_error(conn->ssl_iostream);
		if (error == NULL) {
			error = conn->input->stream_errno == 0 ? "EOF" :
				strerror(conn->input->stream_errno);
		}
		server_connection_callback(conn, SERVER_EXIT_CODE_DISCONNECTED,
					   error);
	}
	if (printing_conn == conn)
		print_connection_released();

	timeout_remove(&conn->to_input);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	i_stream_destroy(&conn->cmd_input);
	/* close cmd_output after its parent, so the "." isn't sent */
	o_stream_destroy(&conn->cmd_output);
	ssl_iostream_destroy(&conn->ssl_iostream);
	io_remove(&conn->io_log);
	/* make sure all logs got consumed */
	if (conn->log_input != NULL)
		server_connection_print_log(conn);
	i_stream_unref(&conn->log_input);
	io_remove(&conn->io);
	i_close_fd(&conn->fd);
	pool_unref(&conn->pool);
}

struct doveadm_server *
server_connection_get_server(struct server_connection *conn)
{
	return conn->server;
}

void server_connection_cmd(struct server_connection *conn, const char *line,
			   struct istream *cmd_input,
			   server_cmd_callback_t *callback, void *context)
{
	i_assert(conn->delayed_cmd == NULL);

	conn->state = SERVER_REPLY_STATE_PRINT;
	if (cmd_input != NULL) {
		i_assert(conn->cmd_input == NULL);
		i_stream_ref(cmd_input);
		conn->cmd_input = cmd_input;
	}
	if (!conn->authenticated)
		conn->delayed_cmd = p_strdup(conn->pool, line);
	else {
		o_stream_nsend_str(conn->output, line);
		server_connection_send_cmd_input(conn);
	}
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
	io_remove(&conn->io);
	conn->fd = -1;
}
