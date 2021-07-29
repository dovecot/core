/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "connection.h"
#include "istream.h"
#include "istream-multiplex.h"
#include "ostream.h"
#include "ostream-dot.h"
#include "str.h"
#include "strescape.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "doveadm.h"
#include "doveadm-print.h"
#include "doveadm-util.h"
#include "doveadm-server.h"
#include "server-connection.h"

#define DOVEADM_LOG_CHANNEL_ID 'L'

#define MAX_INBUF_SIZE (1024*32)

#define DOVEADM_PROTO_MINOR_MIN_MULTIPLEX 1
#define DOVEADM_PROTO_MINOR_MIN_STARTTLS 2
#define DOVEADM_PROTO_MINOR_MIN_PROXY_TTL 3

enum server_reply_state {
	SERVER_REPLY_STATE_DONE = 0,
	SERVER_REPLY_STATE_PRINT,
	SERVER_REPLY_STATE_RET
};

struct server_connection {
	struct connection conn;
	struct doveadm_server *server;

	pool_t pool;
	struct io *io_log;
	struct istream *log_input;
	struct ssl_iostream *ssl_iostream;

	struct istream *cmd_input;
	struct ostream *cmd_output;
	const char *delayed_cmd;
	int delayed_cmd_proxy_ttl;
	server_cmd_callback_t *callback;
	void *context;

	enum server_reply_state state;

	bool authenticate_sent:1;
	bool authenticated:1;
	bool streaming:1;
	bool ssl_done:1;
};

static struct server_connection *printing_conn = NULL;
static ARRAY(struct doveadm_server *) print_pending_servers = ARRAY_INIT;

static bool server_connection_input_one(struct server_connection *conn);
static int server_connection_init_ssl(struct server_connection *conn,
				      const char **error_r);
static void server_connection_destroy(struct server_connection **_conn);

static void server_set_print_pending(struct doveadm_server *server)
{
	struct doveadm_server *pending_server;

	if (!array_is_created(&print_pending_servers))
		i_array_init(&print_pending_servers, 16);
	array_foreach_elem(&print_pending_servers, pending_server) {
		if (pending_server == server)
			return;
	}
	array_push_back(&print_pending_servers, &server);
}

static void server_print_connection_released(struct doveadm_server *server)
{
	struct connection *conn;

	conn = server->connections->connections;
	for (; conn != NULL; conn = conn->next)
		connection_input_resume(conn);
}

static void print_connection_released(void)
{
	struct doveadm_server *server;

	printing_conn = NULL;
	if (!array_is_created(&print_pending_servers))
		return;

	array_foreach_elem(&print_pending_servers, server)
		server_print_connection_released(server);
	array_free(&print_pending_servers);
}

static int server_connection_send_cmd_input_more(struct server_connection *conn)
{
	enum ostream_send_istream_result res;
	int ret = -1;

	/* ostream-dot writes only up to max buffer size, so keep it non-zero */
	o_stream_set_max_buffer_size(conn->cmd_output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(conn->cmd_output, conn->cmd_input);
	o_stream_set_max_buffer_size(conn->cmd_output, SIZE_MAX);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		return 1;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		e_error(conn->conn.event, "read() failed: %s",
			i_stream_get_error(conn->cmd_input));
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		e_error(conn->conn.event, "write() failed: %s",
			o_stream_get_error(conn->cmd_output));
		break;
	}
	if (res == OSTREAM_SEND_ISTREAM_RESULT_FINISHED) {
		if ((ret = o_stream_finish(conn->cmd_output)) == 0)
			return 0;
		else if (ret < 0) {
			e_error(conn->conn.event, "write() failed: %s",
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

	conn->cmd_output = o_stream_create_dot(conn->conn.output, TRUE);
	(void)server_connection_send_cmd_input_more(conn);
}

static int server_connection_output(struct server_connection *conn)
{
	int ret;

	ret = o_stream_flush(conn->conn.output);
	if (ret > 0 && conn->cmd_input != NULL && conn->delayed_cmd == NULL)
		ret = server_connection_send_cmd_input_more(conn);
	if (ret < 0)
		server_connection_destroy(&conn);
	return ret;
}

static void
server_connection_callback(struct server_connection *conn,
			   const struct doveadm_server_reply *reply)
{
	server_cmd_callback_t *callback = conn->callback;

	i_assert(reply->exit_code == 0 || reply->error != NULL);

	conn->callback = NULL;
	callback(reply, conn->context);
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
		io_remove(&conn->conn.io);
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
				e_error(conn->conn.event,
					"doveadm server sent broken print input");
				server_connection_destroy(&conn);
				return;
			}
			conn->state = SERVER_REPLY_STATE_RET;
			i_stream_skip(conn->conn.input, i + 1);

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
	i_stream_skip(conn->conn.input, size);
}

static void
server_connection_send_cmd(struct server_connection *conn,
			   const char *cmdline, int proxy_ttl)
{
	i_assert(conn->authenticated);
	i_assert(proxy_ttl >= 1);

	if (conn->conn.minor_version < DOVEADM_PROTO_MINOR_MIN_PROXY_TTL) {
		o_stream_nsend_str(conn->conn.output, cmdline);
		return;
	}

	/* <flags> <username> <command> [<args>] -
	   Insert --proxy-ttl as the first arg. */
	const char *p = strchr(cmdline, '\t');
	i_assert(p != NULL);
	p = strchr(p+1, '\t');
	i_assert(p != NULL);
	p = strchr(p+1, '\t');
	i_assert(p != NULL);
	size_t prefix_len = p - cmdline;

	const char *proxy_ttl_str = t_strdup_printf(
		"\t--proxy-ttl\t%d", proxy_ttl);
	struct const_iovec iov[] = {
		{ cmdline, prefix_len },
		{ proxy_ttl_str, strlen(proxy_ttl_str) },
		{ cmdline + prefix_len, strlen(cmdline + prefix_len) },
	};
	o_stream_nsendv(conn->conn.output, iov, N_ELEMENTS(iov));
}

static void server_connection_authenticated(struct server_connection *conn)
{
	conn->authenticated = TRUE;
	if (conn->delayed_cmd != NULL) {
		server_connection_send_cmd(conn, conn->delayed_cmd,
					   conn->delayed_cmd_proxy_ttl);
		conn->delayed_cmd = NULL;
		server_connection_send_cmd_input(conn);
	}
}

static int
server_connection_authenticate(struct server_connection *conn)
{
	string_t *plain = t_str_new(128);
	string_t *cmd = t_str_new(128);

	if (*conn->server->password == '\0') {
		e_error(conn->conn.event, "doveadm_password not set, "
			"can't authenticate to remote server");
		return -1;
	}

	str_append_c(plain, '\0');
	str_append(plain, conn->server->username);
	str_append_c(plain, '\0');
	str_append(plain, conn->server->password);

	str_append(cmd, "PLAIN\t");
	base64_encode(plain->data, plain->used, cmd);
	str_append_c(cmd, '\n');

	o_stream_nsend(conn->conn.output, cmd->data, cmd->used);
	conn->authenticate_sent = TRUE;
	return 0;
}

static void server_log_disconnect_error(struct server_connection *conn)
{
	const char *error;

	error = conn->ssl_iostream == NULL ? NULL :
		ssl_iostream_get_last_error(conn->ssl_iostream);
	if (error == NULL)
		error = connection_disconnect_reason(&conn->conn);
	e_error(conn->conn.event,
		"doveadm server disconnected before handshake: %s", error);
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
			e_error(conn->conn.event,
				"Doveadm server sent invalid log type 0x%02x",
				line[0]);
		line++;
		i_log_type(&ctx, "remote(%s): %s", conn->server->name, line);
	}
}

static void server_connection_start_multiplex(struct server_connection *conn)
{
	struct istream *is = conn->conn.input;
	conn->conn.input = i_stream_create_multiplex(is, MAX_INBUF_SIZE);
	i_stream_unref(&is);

	conn->log_input = i_stream_multiplex_add_channel(conn->conn.input,
							 DOVEADM_LOG_CHANNEL_ID);
	conn->io_log = io_add_istream(conn->log_input, server_connection_print_log, conn);
	i_stream_set_return_partial_line(conn->log_input, TRUE);

	/* recreate IO using multiplex istream */
	connection_streams_changed(&conn->conn);
}

static void server_connection_input(struct connection *_conn)
{
	struct server_connection *conn =
		container_of(_conn, struct server_connection, conn);
	const char *line;
	const char *error;

	if (i_stream_read(conn->conn.input) < 0) {
		/* disconnected */
		server_log_disconnect_error(conn);
		server_connection_destroy(&conn);
		return;
	}

	while (!conn->authenticated) {
		if ((line = i_stream_next_line(conn->conn.input)) == NULL) {
			if (conn->conn.input->eof) {
				/* we'll also get here if the line is too long */
				server_log_disconnect_error(conn);
				server_connection_destroy(&conn);
			}
			return;
		}
		/* Allow VERSION before or after the "+" or "-" line,
		   because v2.2.33 sent the version after and newer
		   versions send before. */
		if (!conn->conn.version_received &&
		    str_begins(line, "VERSION\t")) {
			if (!version_string_verify_full(line, "doveadm-client",
							DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR,
							&conn->conn.minor_version)) {
				e_error(conn->conn.event,
					"doveadm server not compatible with this client"
					"(mixed old and new binaries?)");
				server_connection_destroy(&conn);
				return;
			}
			conn->conn.version_received = TRUE;
		} else if (strcmp(line, "+") == 0) {
			if (conn->conn.minor_version >= DOVEADM_PROTO_MINOR_MIN_MULTIPLEX)
				server_connection_start_multiplex(conn);
			server_connection_authenticated(conn);
		} else if (strcmp(line, "-") == 0) {
			if (conn->authenticate_sent) {
				e_error(conn->conn.event,
					"doveadm authentication failed (%s)",
					line+1);
				server_connection_destroy(&conn);
				return;
			}
			if (!conn->ssl_done &&
			    (conn->server->ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) != 0) {
				connection_input_halt(&conn->conn);
				if (conn->conn.minor_version < DOVEADM_PROTO_MINOR_MIN_STARTTLS) {
					e_error(conn->conn.event,
						"doveadm STARTTLS failed: Server does not support it");
					server_connection_destroy(&conn);
					return;
				}
				/* send STARTTLS */
				o_stream_nsend_str(conn->conn.output, "STARTTLS\n");
				if (server_connection_init_ssl(conn, &error) < 0) {
					e_error(conn->conn.event,
						"doveadm STARTTLS failed: %s", error);
					server_connection_destroy(&conn);
					return;
				}
				conn->ssl_done = TRUE;
				connection_input_resume(&conn->conn);
			}
			if (server_connection_authenticate(conn) < 0) {
				server_connection_destroy(&conn);
				return;
			}
		} else {
			e_error(conn->conn.event,
				"doveadm server sent invalid handshake: %s",
				line);
			server_connection_destroy(&conn);
			return;
		}
	}

	while (server_connection_input_one(conn)) ;
}

static void
server_connection_input_cmd_error(struct server_connection *conn,
				  const char *line)
{
	const char *code, *args = strchr(line, ' ');
	if (args != NULL)
		code = t_strdup_until(line, args++);
	else {
		code = line;
		args = "";
	}
	struct doveadm_server_reply reply = {
		.exit_code = doveadm_str_to_exit_code(code),
		.error = line,
	};
	switch (reply.exit_code) {
	case DOVEADM_EX_REFERRAL:
		reply.error = args;
		break;
	}
	server_connection_callback(conn, &reply);
}

static bool server_connection_input_one(struct server_connection *conn)
{
	const unsigned char *data;
	size_t size;
	const char *line;

	/* check logs - NOTE: must be before i_stream_get_data() since checking
	   for logs may add data to our channel. */
	if (conn->log_input != NULL)
		(void)server_connection_print_log(conn);

	data = i_stream_get_data(conn->conn.input, &size);
	if (size == 0)
		return FALSE;

	switch (conn->state) {
	case SERVER_REPLY_STATE_DONE:
		e_error(conn->conn.event,
			"doveadm server sent unexpected input");
		server_connection_destroy(&conn);
		return FALSE;
	case SERVER_REPLY_STATE_PRINT:
		server_handle_input(conn, data, size);
		if (conn->state != SERVER_REPLY_STATE_RET)
			return FALSE;
		/* fall through */
	case SERVER_REPLY_STATE_RET:
		line = i_stream_next_line(conn->conn.input);
		if (line == NULL)
			return FALSE;

		if (line[0] == '+') {
			struct doveadm_server_reply reply = {
				.exit_code = 0,
			};
			server_connection_callback(conn, &reply);
		} else if (line[0] == '-') {
			server_connection_input_cmd_error(conn, line+1);
		} else {
			e_error(conn->conn.event,
				"doveadm server sent broken input "
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

static int server_connection_init_ssl(struct server_connection *conn,
				      const char **error_r)
{
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (conn->server->ssl_flags == 0)
		return 0;

	doveadm_get_ssl_settings(&ssl_set, pool_datastack_create());

	if ((conn->server->ssl_flags & AUTH_PROXY_SSL_FLAG_ANY_CERT) != 0)
		ssl_set.allow_invalid_cert = TRUE;
	if (ssl_set.allow_invalid_cert)
		ssl_set.verbose_invalid_cert = TRUE;

	if (conn->server->ssl_ctx == NULL &&
	    ssl_iostream_client_context_cache_get(&ssl_set,
						  &conn->server->ssl_ctx,
						  &error) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL client: %s", error);
		return -1;
	}

	connection_input_halt(&conn->conn);
	if (io_stream_create_ssl_client(conn->server->ssl_ctx,
					conn->server->hostname, &ssl_set,
					&conn->conn.input, &conn->conn.output,
					&conn->ssl_iostream, &error) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL client: %s", error);
		return -1;
	}
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		*error_r = t_strdup_printf(
			"SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}
	connection_input_resume(&conn->conn);
	return 0;
}

static void server_connection_destroy_conn(struct connection *_conn)
{
	struct server_connection *conn =
		container_of(_conn, struct server_connection, conn);
	server_connection_destroy(&conn);
}

static const struct connection_vfuncs doveadm_client_vfuncs = {
	.input = server_connection_input,
	.destroy = server_connection_destroy_conn,
};

static struct connection_settings doveadm_client_set = {
	/* Note: These service names are reversed compared to how they usually
	   work. Too late to change now without breaking the protocol. */
	.service_name_in = "doveadm-client",
	.service_name_out = "doveadm-server",
	.major_version = DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR,
	.minor_version = DOVEADM_SERVER_PROTOCOL_VERSION_MINOR,
	.dont_send_version = TRUE, /* doesn't work with SSL */
	.input_max_size = MAX_INBUF_SIZE,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
};

int server_connection_create(struct doveadm_server *server,
			     struct server_connection **conn_r,
			     const char **error_r)
{
	const char *target;
	struct server_connection *conn;
	pool_t pool;

	i_assert(server->username != NULL);
	i_assert(server->password != NULL);

	if (server->connections == NULL) {
		server->connections =
			connection_list_init(&doveadm_client_set,
					     &doveadm_client_vfuncs);
	}

	pool = pool_alloconly_create("doveadm server connection", 1024*16);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;
	conn->server = server;
	if (server->ip.family != 0) {
		(void)net_ipport2str(&server->ip, server->port, &target);
	} else {
		target = server->name;
	}
	int fd = doveadm_connect_with_default_port(target,
			doveadm_settings->doveadm_port);
	net_set_nonblock(fd, TRUE);
	connection_init_client_fd(server->connections, &conn->conn,
				  server->hostname, fd, fd);

	o_stream_set_flush_callback(conn->conn.output,
				    server_connection_output, conn);

	if (((server->ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) == 0 &&
	     server_connection_init_ssl(conn, error_r) < 0)) {
		server_connection_destroy(&conn);
		return -1;
	}

	conn->state = SERVER_REPLY_STATE_DONE;
	o_stream_nsend_str(conn->conn.output,
			   DOVEADM_SERVER_PROTOCOL_VERSION_LINE"\n");

	*conn_r = conn;
	return 0;
}

static void server_connection_destroy(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;
	const char *error;

	*_conn = NULL;

	if (conn->callback != NULL) {
		error = conn->ssl_iostream == NULL ? NULL :
			ssl_iostream_get_last_error(conn->ssl_iostream);
		if (error == NULL)
			error = connection_disconnect_reason(&conn->conn);
		struct doveadm_server_reply reply = {
			.exit_code = SERVER_EXIT_CODE_DISCONNECTED,
			.error = error,
		};
		server_connection_callback(conn, &reply);
	}
	if (printing_conn == conn)
		print_connection_released();

	/* close cmd_output after its parent, so the "." isn't sent */
	o_stream_close(conn->conn.output);
	o_stream_destroy(&conn->cmd_output);

	i_stream_unref(&conn->cmd_input);
	ssl_iostream_destroy(&conn->ssl_iostream);
	io_remove(&conn->io_log);
	/* make sure all logs got consumed before closing the fd */
	if (conn->log_input != NULL)
		server_connection_print_log(conn);
	i_stream_unref(&conn->log_input);

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

void server_connection_get_dest(struct server_connection *conn,
				struct ip_addr *ip_r, in_port_t *port_r)
{
	if (net_getpeername(conn->conn.fd_in, ip_r, port_r) < 0) {
		i_zero(ip_r);
		*port_r = 0;
	}
}

void server_connection_cmd(struct server_connection *conn, int proxy_ttl,
			   const char *line, struct istream *cmd_input,
			   server_cmd_callback_t *callback, void *context)
{
	i_assert(conn->delayed_cmd == NULL);
	i_assert(proxy_ttl >= 1);

	conn->state = SERVER_REPLY_STATE_PRINT;
	if (cmd_input != NULL) {
		i_assert(conn->cmd_input == NULL);
		i_stream_ref(cmd_input);
		conn->cmd_input = cmd_input;
	}
	if (!conn->authenticated) {
		conn->delayed_cmd_proxy_ttl = proxy_ttl;
		conn->delayed_cmd = p_strdup(conn->pool, line);
	} else {
		server_connection_send_cmd(conn, line, proxy_ttl);
		server_connection_send_cmd_input(conn);
	}
	conn->callback = callback;
	conn->context = context;
}

void server_connection_extract(struct server_connection *conn,
			       struct istream **istream_r,
			       struct ostream **ostream_r,
			       struct ssl_iostream **ssl_iostream_r)
{
	*istream_r = conn->conn.input;
	*ostream_r = conn->conn.output;
	*ssl_iostream_r = conn->ssl_iostream;

	conn->conn.input = NULL;
	conn->conn.output = NULL;
	conn->ssl_iostream = NULL;
	io_remove(&conn->conn.io);
	conn->conn.fd_in = -1;
	conn->conn.fd_out = -1;
}
