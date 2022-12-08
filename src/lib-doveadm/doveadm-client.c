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
#include "doveadm-protocol.h"
#include "doveadm-client.h"
#include "dns-lookup.h"

#include <sysexits.h>

#define DOVEADM_LOG_CHANNEL_ID 'L'

#define MAX_INBUF_SIZE (1024*32)

#define DOVEADM_CLIENT_DNS_TIMEOUT_MSECS (1000*10)

enum doveadm_client_reply_state {
	DOVEADM_CLIENT_REPLY_STATE_DONE = 0,
	DOVEADM_CLIENT_REPLY_STATE_PRINT,
	DOVEADM_CLIENT_REPLY_STATE_RET
};

struct doveadm_client {
	struct connection conn;

	int refcount;
	struct doveadm_client_settings set;

	pool_t pool;
	struct timeout *to_destroy;
	struct timeout *to_create_failed;
	struct io *io_log;
	struct istream *log_input;
	struct ssl_iostream *ssl_iostream;

	struct istream *cmd_input;
	struct ostream *cmd_output;
	const char *delayed_cmd;
	struct doveadm_client_cmd_settings delayed_set;
	doveadm_client_cmd_callback_t *callback;

	struct dns_lookup *dns_lookup;
	unsigned int ips_count;
	struct ip_addr *ips;

	void *context;

	doveadm_client_print_t *print_callback;
	void *print_context;

	enum doveadm_client_reply_state state;

	bool destroyed:1;
	bool authenticate_sent:1;
	bool authenticated:1;
	bool ssl_done:1;
};

static struct connection_list *doveadm_clients = NULL;
static struct doveadm_client *printing_conn = NULL;
static ARRAY(struct doveadm_client *) print_pending_connections = ARRAY_INIT;

static bool doveadm_client_input_one(struct doveadm_client *conn);
static int doveadm_client_init_ssl(struct doveadm_client *conn,
				   const char **error_r);
static void doveadm_client_destroy(struct doveadm_client **_conn);
static void doveadm_client_destroy_conn(struct connection *_conn);

void doveadm_client_settings_dup(const struct doveadm_client_settings *src,
				 struct doveadm_client_settings *dest_r,
				 pool_t pool)
{
	i_zero(dest_r);

	dest_r->socket_path = p_strdup(pool, src->socket_path);
	dest_r->hostname = p_strdup(pool, src->hostname);
	dest_r->ip = src->ip;
	dest_r->port = src->port;

	dest_r->dns_client_socket_path = src->dns_client_socket_path != NULL ?
		p_strdup(pool, src->dns_client_socket_path) : "";

	dest_r->username = p_strdup(pool, src->username);
	dest_r->password = p_strdup(pool, src->password);

	dest_r->ssl_flags = src->ssl_flags;
	dest_r->ssl_set = *ssl_iostream_settings_dup(pool, &src->ssl_set);
	if (src->ssl_ctx != NULL) {
		dest_r->ssl_ctx = src->ssl_ctx;
		ssl_iostream_context_ref(dest_r->ssl_ctx);
	}

	dest_r->log_passthrough = src->log_passthrough;
}

static void doveadm_client_set_print_pending(struct doveadm_client *conn)
{
	if (!array_is_created(&print_pending_connections))
		i_array_init(&print_pending_connections, 16);
	array_push_back(&print_pending_connections, &conn);
}

static void print_connection_released(void)
{
	struct doveadm_client *conn;

	printing_conn = NULL;
	if (!array_is_created(&print_pending_connections))
		return;

	array_foreach_elem(&print_pending_connections, conn)
		connection_input_resume(&conn->conn);
	array_free(&print_pending_connections);
}

static int doveadm_client_send_cmd_input_more(struct doveadm_client *conn)
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
		e_error(conn->conn.event, "read(%s) failed: %s",
			i_stream_get_name(conn->cmd_input),
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

	i_stream_unref(&conn->cmd_input);
	o_stream_destroy(&conn->cmd_output);
	return ret;
}

static void doveadm_client_send_cmd_input(struct doveadm_client *conn)
{
	if (conn->cmd_input == NULL)
		return;

	conn->cmd_output = o_stream_create_dot(conn->conn.output, TRUE);
	if (doveadm_client_send_cmd_input_more(conn) < 0) {
		i_assert(conn->to_destroy == NULL);
		conn->to_destroy = timeout_add_short(0,
			doveadm_client_destroy_conn, &conn->conn);
	}
}

static int doveadm_client_output(struct doveadm_client *conn)
{
	int ret;

	ret = o_stream_flush(conn->conn.output);
	if (ret > 0 && conn->cmd_input != NULL && conn->delayed_cmd == NULL)
		ret = doveadm_client_send_cmd_input_more(conn);
	if (ret < 0)
		doveadm_client_destroy(&conn);
	return ret;
}

static void
doveadm_client_callback(struct doveadm_client *conn,
			const struct doveadm_server_reply *reply)
{
	doveadm_client_cmd_callback_t *callback = conn->callback;

	i_assert(reply->exit_code == 0 || reply->error != NULL);

	conn->callback = NULL;
	callback(reply, conn->context);
}

static void
doveadm_client_handle_input(struct doveadm_client *conn,
			    const unsigned char *data, size_t size)
{
	size_t i, start;

	if (printing_conn == conn) {
		/* continue printing */
	} else if (printing_conn == NULL) {
		printing_conn = conn;
	} else {
		/* someone else is printing. don't continue until it
		   goes away */
		doveadm_client_set_print_pending(conn);
		io_remove(&conn->conn.io);
		return;
	}

	if (data[size-1] == '\001') {
		/* last character is an escape */
		size--;
	}

	for (i = start = 0; i < size; i++) {
		if (data[i] == '\n') {
			if (i != start) {
				e_error(conn->conn.event,
					"doveadm server sent broken print input");
				doveadm_client_destroy(&conn);
				return;
			}
			conn->state = DOVEADM_CLIENT_REPLY_STATE_RET;
			i_stream_skip(conn->conn.input, i + 1);

			print_connection_released();
			return;
		}
		if (data[i] == '\t') {
			if (conn->print_callback != NULL) T_BEGIN {
				conn->print_callback(data + start, i - start,
						     TRUE, conn->print_context);
			} T_END;
			start = i + 1;
		}
	}
	if (start != size && conn->print_callback != NULL) T_BEGIN {
		conn->print_callback(data + start, size - start, FALSE,
				     conn->print_context);
	} T_END;
	i_stream_skip(conn->conn.input, size);
}

static void
doveadm_client_send_cmd(struct doveadm_client *conn,
			const char *cmdline,
			const struct doveadm_client_cmd_settings *set)
{
	unsigned int i;

	i_assert(conn->authenticated);
	i_assert(set->proxy_ttl >= 1);

	if (conn->conn.minor_version < DOVEADM_PROTOCOL_MIN_VERSION_EXTRA_FIELDS) {
		o_stream_nsend_str(conn->conn.output, cmdline);
		return;
	}

	/* <flags + x> <extra fields> <username> <command> [<args>] */
	const char *p = strchr(cmdline, '\t');
	i_assert(p != NULL);
	size_t prefix_len = p - cmdline;

	string_t *extra_fields = t_str_new(128);
	str_printfa(extra_fields, "proxy-ttl=%d", set->proxy_ttl);
	if (set->forward_fields != NULL) {
		for (i = 0; set->forward_fields[i] != NULL; i++) {
			str_append(extra_fields, "\tforward=");
			str_append_tabescaped(extra_fields,
					      set->forward_fields[i]);
		}
	}
	const char *extra_fields_escaped = str_tabescape(str_c(extra_fields));

	const char flags[] = {
		DOVEADM_PROTOCOL_CMD_FLAG_EXTRA_FIELDS,
		'\t'
	};
	struct const_iovec iov[] = {
		{ cmdline, prefix_len },
		{ flags, N_ELEMENTS(flags) },
		{ extra_fields_escaped, strlen(extra_fields_escaped) },
		{ cmdline + prefix_len, strlen(cmdline + prefix_len) },
	};
	o_stream_nsendv(conn->conn.output, iov, N_ELEMENTS(iov));
}

static int
doveadm_client_authenticate(struct doveadm_client *conn)
{
	string_t *plain = t_str_new(128);
	string_t *cmd = t_str_new(128);

	if (*conn->set.password == '\0') {
		e_error(conn->conn.event, "doveadm_password not set, "
			"can't authenticate to remote server");
		return -1;
	}

	str_append_c(plain, '\0');
	str_append(plain, conn->set.username);
	str_append_c(plain, '\0');
	str_append(plain, conn->set.password);

	str_append(cmd, "PLAIN\t");
	base64_encode(plain->data, plain->used, cmd);
	str_append_c(cmd, '\n');

	o_stream_nsend(conn->conn.output, cmd->data, cmd->used);
	conn->authenticate_sent = TRUE;
	return 0;
}

static void doveadm_client_log_disconnect_error(struct doveadm_client *conn)
{
	const char *error;

	error = conn->ssl_iostream == NULL ? NULL :
		ssl_iostream_get_last_error(conn->ssl_iostream);
	if (error == NULL)
		error = connection_disconnect_reason(&conn->conn);
	e_error(conn->conn.event,
		"doveadm server disconnected before handshake: %s", error);
}

static void doveadm_client_print_log(struct doveadm_client *conn)
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
		i_log_type(&ctx, "remote(%s): %s", conn->conn.name, line);
	}
}

static void doveadm_client_start_multiplex(struct doveadm_client *conn)
{
	struct istream *is = conn->conn.input;
	conn->conn.input = i_stream_create_multiplex(is, MAX_INBUF_SIZE);
	i_stream_unref(&is);

	conn->log_input = i_stream_multiplex_add_channel(conn->conn.input,
							 DOVEADM_LOG_CHANNEL_ID);
	conn->io_log = io_add_istream(conn->log_input, doveadm_client_print_log, conn);
	i_stream_set_return_partial_line(conn->log_input, TRUE);

	/* recreate IO using multiplex istream */
	connection_streams_changed(&conn->conn);
}

static void doveadm_client_authenticated(struct doveadm_client *conn)
{
	conn->authenticated = TRUE;

	if (conn->conn.minor_version >= DOVEADM_PROTOCOL_MIN_VERSION_MULTIPLEX)
		doveadm_client_start_multiplex(conn);

	if (conn->set.log_passthrough &&
	    conn->conn.minor_version >= DOVEADM_PROTOCOL_MIN_VERSION_LOG_PASSTHROUGH)
		o_stream_nsend_str(conn->conn.output, "\t\tOPTION\tlog-passthrough\n");

	if (conn->delayed_cmd != NULL) {
		doveadm_client_send_cmd(conn, conn->delayed_cmd,
					&conn->delayed_set);
		conn->delayed_cmd = NULL;
		doveadm_client_send_cmd_input(conn);
	}
}

static int
doveadm_client_prepare_authentication(struct doveadm_client *conn,
				      const char *line)
{
	const char *error;

	if (conn->authenticate_sent) {
		e_error(conn->conn.event, "doveadm authentication failed (%s)",
			line+1);
		return -1;
	}
	if (!conn->ssl_done &&
	    (conn->set.ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) != 0) {
		connection_input_halt(&conn->conn);
		if (conn->conn.minor_version < DOVEADM_PROTOCOL_MIN_VERSION_STARTTLS) {
			e_error(conn->conn.event,
				"doveadm STARTTLS failed: Server does not support it");
			return -1;
		}
		/* send STARTTLS */
		o_stream_nsend_str(conn->conn.output, "STARTTLS\n");
		if (doveadm_client_init_ssl(conn, &error) < 0) {
			e_error(conn->conn.event,
				"doveadm STARTTLS failed: %s", error);
			return -1;
		}
		conn->ssl_done = TRUE;
		connection_input_resume(&conn->conn);
	}

	if (doveadm_client_authenticate(conn) < 0)
		return -1;
	return 0;
}

static void doveadm_client_input(struct connection *_conn)
{
	struct doveadm_client *conn =
		container_of(_conn, struct doveadm_client, conn);
	const char *line;

	if (i_stream_read(conn->conn.input) < 0) {
		/* disconnected */
		doveadm_client_log_disconnect_error(conn);
		doveadm_client_destroy(&conn);
		return;
	}

	while (!conn->authenticated) {
		if ((line = i_stream_next_line(conn->conn.input)) == NULL) {
			if (conn->conn.input->eof) {
				/* we'll also get here if the line is too long */
				doveadm_client_log_disconnect_error(conn);
				doveadm_client_destroy(&conn);
			}
			return;
		}
		/* Allow VERSION before or after the "+" or "-" line,
		   because v2.2.33 sent the version after and newer
		   versions send before. */
		if (!conn->conn.version_received &&
		    str_begins_with(line, "VERSION\t")) {
			if (!version_string_verify_full(line, "doveadm-client",
							DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR,
							&conn->conn.minor_version)) {
				e_error(conn->conn.event,
					"doveadm server not compatible with this client"
					"(mixed old and new binaries?)");
				doveadm_client_destroy(&conn);
				return;
			}
			conn->conn.version_received = TRUE;
		} else if (strcmp(line, "+") == 0) {
			doveadm_client_authenticated(conn);
		} else if (strcmp(line, "-") == 0) {
			if (doveadm_client_prepare_authentication(conn, line) < 0) {
				doveadm_client_destroy(&conn);
				return;
			}
		} else {
			e_error(conn->conn.event,
				"doveadm server sent invalid handshake: %s",
				line);
			doveadm_client_destroy(&conn);
			return;
		}
	}

	while (doveadm_client_input_one(conn)) ;
}

static void
doveadm_client_input_cmd_error(struct doveadm_client *conn, const char *line)
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
	doveadm_client_callback(conn, &reply);
}

static bool doveadm_client_input_one(struct doveadm_client *conn)
{
	const unsigned char *data;
	size_t size;
	const char *line;

	/* check logs - NOTE: must be before i_stream_get_data() since checking
	   for logs may add data to our channel. */
	if (conn->log_input != NULL)
		(void)doveadm_client_print_log(conn);

	data = i_stream_get_data(conn->conn.input, &size);
	if (size == 0)
		return FALSE;

	switch (conn->state) {
	case DOVEADM_CLIENT_REPLY_STATE_DONE:
		e_error(conn->conn.event,
			"doveadm server sent unexpected input");
		doveadm_client_destroy(&conn);
		return FALSE;
	case DOVEADM_CLIENT_REPLY_STATE_PRINT:
		doveadm_client_handle_input(conn, data, size);
		if (conn->state != DOVEADM_CLIENT_REPLY_STATE_RET)
			return FALSE;
		/* fall through */
	case DOVEADM_CLIENT_REPLY_STATE_RET:
		line = i_stream_next_line(conn->conn.input);
		if (line == NULL)
			return FALSE;

		if (line[0] == '+') {
			struct doveadm_server_reply reply = {
				.exit_code = 0,
			};
			doveadm_client_callback(conn, &reply);
		} else if (line[0] == '-') {
			doveadm_client_input_cmd_error(conn, line+1);
		} else {
			e_error(conn->conn.event,
				"doveadm server sent broken input "
				"(expected cmd reply): %s", line);
			doveadm_client_destroy(&conn);
			return FALSE;
		}
		if (conn->callback == NULL) {
			/* we're finished, close the connection */
			doveadm_client_destroy(&conn);
			return FALSE;
		}
		return TRUE;
	}
	i_unreached();
}

static int doveadm_client_init_ssl(struct doveadm_client *conn,
				   const char **error_r)
{
	struct ssl_iostream_settings ssl_set = conn->set.ssl_set;
	const char *error;

	if (conn->set.ssl_flags == 0)
		return 0;

	if ((conn->set.ssl_flags & AUTH_PROXY_SSL_FLAG_ANY_CERT) != 0)
		ssl_set.allow_invalid_cert = TRUE;
	if (ssl_set.allow_invalid_cert)
		ssl_set.verbose_invalid_cert = TRUE;

	if (conn->set.ssl_ctx == NULL &&
	    ssl_iostream_client_context_cache_get(&ssl_set, &conn->set.ssl_ctx,
						  &error) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL client: %s", error);
		return -1;
	}

	const char *hostname =
		conn->set.hostname != NULL ? conn->set.hostname : "";
	connection_input_halt(&conn->conn);
	if (io_stream_create_ssl_client(conn->set.ssl_ctx, hostname, &ssl_set,
					conn->conn.event,
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

static void doveadm_client_destroy_conn(struct connection *_conn)
{
	struct doveadm_client *conn =
		container_of(_conn, struct doveadm_client, conn);
	doveadm_client_destroy(&conn);
}

static void doveadm_client_connected(struct connection *_conn, bool success)
{
	struct doveadm_client *conn =
		container_of(_conn, struct doveadm_client, conn);
	const char *error;

	if (!success)
		return;

	o_stream_set_flush_callback(conn->conn.output,
				    doveadm_client_output, conn);

	connection_input_halt(&conn->conn);
	if (((conn->set.ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) == 0 &&
	     doveadm_client_init_ssl(conn, &error) < 0)) {
		e_error(conn->conn.event, "%s", error);
		/* Can't safely destroy the connection here, so delay it */
		conn->to_destroy = timeout_add_short(0,
			doveadm_client_destroy_conn, &conn->conn);
		return;
	}
	connection_input_resume(&conn->conn);

	o_stream_nsend_str(conn->conn.output,
			   DOVEADM_SERVER_PROTOCOL_VERSION_LINE"\n");
}

static const struct connection_vfuncs doveadm_client_vfuncs = {
	.input = doveadm_client_input,
	.destroy = doveadm_client_destroy_conn,
	.client_connected = doveadm_client_connected,
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
	.client_connect_timeout_msecs = DOVEADM_TCP_CONNECT_TIMEOUT_SECS*1000,
};

struct doveadm_client_dns_lookup_context {
	struct doveadm_client *conn;
	const char *error;
};

static void doveadm_client_connect_init(struct doveadm_client *conn)
{
	connection_init_client_ip(doveadm_clients, &conn->conn,
				  conn->set.hostname, &conn->ips[0],
				  conn->set.port);
}

static int doveadm_client_connect(struct doveadm_client *conn,
				   const char **error_r)
{
	if (connection_client_connect(&conn->conn) < 0) {
		*error_r = t_strdup_printf("net_connect(%s) failed: %m",
					   conn->conn.name);
		return -1;
	}
	return 0;
}

static void
doveadm_client_create_failed(struct doveadm_client_dns_lookup_context *ctx)
{
	struct doveadm_client *conn = ctx->conn;
	timeout_remove(&conn->to_create_failed);

	struct doveadm_server_reply reply = {
		.exit_code = EX_DATAERR,
		.error  = ctx->error,
	};
	doveadm_client_callback(conn, &reply);
	pool_unref(&conn->pool);
}

static void
doveadm_client_dns_lookup_callback(const struct dns_lookup_result *result,
				   struct doveadm_client_dns_lookup_context *ctx)
{
	struct doveadm_client *conn = ctx->conn;
	const char *error;

	if (result->error != NULL) {
		ctx->error = p_strdup_printf(conn->pool,
					     "dns_lookup(%s) failed: %s",
					     conn->set.hostname, result->error);
		conn->to_create_failed =
			timeout_add_short(0, doveadm_client_create_failed, ctx);
		return;
	}

	i_assert(result->ips_count > 0);
	conn->ips = p_new(conn->pool, struct ip_addr, 1);
	conn->ips[0] = result->ips[0];
	conn->ips_count = 1;

	doveadm_client_connect_init(conn);
	if (doveadm_client_connect(conn, &error) < 0) {
		ctx->error = p_strdup(conn->pool, error);
		conn->to_create_failed =
			timeout_add_short(0, doveadm_client_create_failed, ctx);
	}
}

static int doveadm_client_dns_lookup(struct doveadm_client *conn,
				     const char **error_r)
{
	struct doveadm_client_dns_lookup_context *ctx =
		p_new(conn->pool, struct doveadm_client_dns_lookup_context, 1);
	struct dns_lookup_settings dns_set;

	i_zero(&dns_set);
	dns_set.dns_client_socket_path = conn->set.dns_client_socket_path;
	dns_set.timeout_msecs = DOVEADM_CLIENT_DNS_TIMEOUT_MSECS;
	dns_set.event_parent = conn->conn.event;

	ctx->conn = conn;

	if (dns_lookup(conn->set.hostname, &dns_set,
		       doveadm_client_dns_lookup_callback, ctx,
		       &conn->dns_lookup) != 0) {
		*error_r = t_strdup(ctx->error);
		return -1;
	}
	return 0;
}

static int
doveadm_client_resolve_hostname(struct doveadm_client *conn,
				const char **error_r)
{
	struct ip_addr *ips;
	unsigned int ips_count;
	int ret;

	if (conn->set.dns_client_socket_path[0] != '\0') {
		/* If there is an dns_client_socket_path do a dns
		   lookup. */
		if (doveadm_client_dns_lookup(conn, error_r) < 0)
			return -1;
		return 0;
	}

	ret = net_gethostbyname(conn->set.hostname, &ips, &ips_count);
	if (ret == 0) {
		conn->ips = p_new(conn->pool, struct ip_addr, 1);
		conn->ips[0] = ips[0];
		conn->ips_count = 1;
		doveadm_client_connect_init(conn);
		return 0;
	} else {
		*error_r = t_strdup_printf("Lookup of host %s failed: %s",
					   conn->set.hostname,
					   net_gethosterror(ret));
		return -1;
	}
}

int doveadm_client_create(const struct doveadm_client_settings *set,
			  struct doveadm_client **conn_r,
			  const char **error_r)
{
	struct doveadm_client *conn;
	const char *error;
	pool_t pool;

	i_assert(set->username != NULL);
	i_assert(set->password != NULL);

	if (doveadm_clients == NULL) {
		doveadm_clients =
			connection_list_init(&doveadm_client_set,
					     &doveadm_client_vfuncs);
	}

	pool = pool_alloconly_create("doveadm server connection", 1024*16);
	conn = p_new(pool, struct doveadm_client, 1);
	conn->pool = pool;
	conn->refcount = 1;
	doveadm_client_settings_dup(set, &conn->set, pool);

	if (set->socket_path != NULL) {
		connection_init_client_unix(doveadm_clients, &conn->conn,
					    set->socket_path);
	} else if (set->ip.family != 0) {
		connection_init_client_ip(doveadm_clients, &conn->conn,
					  set->hostname, &set->ip, set->port);

	} else if (doveadm_client_resolve_hostname(conn, &error) != 0) {
		*error_r = t_strdup(error);
		pool_unref(&pool);
		return -1;
	}

	if (conn->dns_lookup == NULL) {
		/* Only connect here if this is not using an async dns
		   lookup. */
		if (doveadm_client_connect(conn, error_r) < 0) {
			connection_deinit(&conn->conn);
			pool_unref(&pool);
			return -1;
		}
		conn->state = DOVEADM_CLIENT_REPLY_STATE_DONE;
	}

	*conn_r = conn;
	return 0;
}

#undef doveadm_client_set_print
void doveadm_client_set_print(struct doveadm_client *conn,
			      doveadm_client_print_t *callback,
			      void *context)
{
	conn->print_callback = callback;
	conn->print_context = context;
}

static void doveadm_client_destroy_int(struct doveadm_client *conn)
{
	const char *error;

	if (conn->callback != NULL) {
		error = conn->ssl_iostream == NULL ? NULL :
			ssl_iostream_get_last_error(conn->ssl_iostream);
		if (error == NULL)
			error = connection_disconnect_reason(&conn->conn);
		struct doveadm_server_reply reply = {
			.exit_code = DOVEADM_CLIENT_EXIT_CODE_DISCONNECTED,
			.error = error,
		};
		doveadm_client_callback(conn, &reply);
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
		doveadm_client_print_log(conn);
	i_stream_unref(&conn->log_input);
	timeout_remove(&conn->to_destroy);

	connection_deinit(&conn->conn);
	ssl_iostream_context_unref(&conn->set.ssl_ctx);
}

static void doveadm_client_destroy(struct doveadm_client **_conn)
{
	struct doveadm_client *conn = *_conn;

	*_conn = NULL;

	conn->destroyed = TRUE;
	timeout_remove(&conn->to_create_failed);
	doveadm_client_destroy_int(conn);
	doveadm_client_unref(&conn);
}

void doveadm_client_unref(struct doveadm_client **_conn)
{
	struct doveadm_client *conn = *_conn;

	*_conn = NULL;

	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;
	if (!conn->destroyed)
		doveadm_client_destroy_int(conn);
	pool_unref(&conn->pool);
}

void doveadm_client_get_dest(struct doveadm_client *conn,
			     struct ip_addr *ip_r, in_port_t *port_r)
{
	if (net_getpeername(conn->conn.fd_in, ip_r, port_r) < 0) {
		i_zero(ip_r);
		*port_r = 0;
	}
}

const struct doveadm_client_settings *
doveadm_client_get_settings(struct doveadm_client *conn)
{
	return &conn->set;
}

static void
doveadm_client_cmd_settings_dup(pool_t pool,
				const struct doveadm_client_cmd_settings *src,
				struct doveadm_client_cmd_settings *dest_r)
{
	i_zero(dest_r);
	dest_r->proxy_ttl = src->proxy_ttl;
	dest_r->forward_fields = src->forward_fields == NULL ? NULL :
		p_strarray_dup(pool, src->forward_fields);
}

void doveadm_client_cmd(struct doveadm_client *conn,
			const struct doveadm_client_cmd_settings *set,
			const char *line, struct istream *cmd_input,
			doveadm_client_cmd_callback_t *callback, void *context)
{
	i_assert(conn->delayed_cmd == NULL);
	i_assert(set->proxy_ttl >= 1);

	conn->state = DOVEADM_CLIENT_REPLY_STATE_PRINT;
	if (cmd_input != NULL) {
		i_assert(conn->cmd_input == NULL);
		i_stream_ref(cmd_input);
		conn->cmd_input = cmd_input;
	}
	if (!conn->authenticated) {
		doveadm_client_cmd_settings_dup(conn->pool, set,
						&conn->delayed_set);
		conn->delayed_cmd = p_strdup(conn->pool, line);
	} else {
		doveadm_client_send_cmd(conn, line, set);
		doveadm_client_send_cmd_input(conn);
	}
	conn->callback = callback;
	conn->context = context;
	/* doveadm_client_destroy() will be called to unreference */
	conn->refcount++;
}

void doveadm_client_extract(struct doveadm_client *conn,
			    struct istream **istream_r,
			    struct istream **log_istream_r,
			    struct ostream **ostream_r,
			    struct ssl_iostream **ssl_iostream_r)
{
	*istream_r = conn->conn.input;
	*log_istream_r = conn->log_input;
	*ostream_r = conn->conn.output;
	*ssl_iostream_r = conn->ssl_iostream;

	o_stream_unset_flush_callback(conn->conn.output);

	conn->conn.input = NULL;
	conn->log_input = NULL;
	conn->conn.output = NULL;
	conn->ssl_iostream = NULL;
	io_remove(&conn->conn.io);
	conn->conn.fd_in = -1;
	conn->conn.fd_out = -1;
}

unsigned int doveadm_clients_count(void)
{
	return doveadm_clients == NULL ? 0 : doveadm_clients->connections_count;
}

void doveadm_clients_destroy_all(void)
{
	connection_list_deinit(&doveadm_clients);
}
