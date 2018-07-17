/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "connection.h"
#include "test-common.h"
#include "smtp-address.h"
#include "smtp-reply-parser.h"
#include "smtp-server.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define SERVER_MAX_TIMEOUT_MSECS 10*1000

/*
 * Types
 */

struct server_connection {
	void *context;
};

struct client_connection {
	struct connection conn;
	void *context;

	pool_t pool;
};

typedef void (*test_server_init_t)
	(const struct smtp_server_settings *server_set);
typedef void (*test_client_init_t)(unsigned int index);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t bind_port = 0;
static struct ioloop *ioloop;
static bool debug = FALSE;
static volatile bool killing_children = FALSE;

/* server */
static struct smtp_server *smtp_server = NULL;
static struct io *io_listen;
static int fd_listen = -1;
static struct smtp_server_callbacks server_callbacks;
static unsigned int server_pending;

/* client */
static pid_t *client_pids = NULL;
static struct connection_list *client_conn_list;
static unsigned int client_pids_count = 0;
static unsigned int client_index;
static void (*test_client_connected)(struct client_connection *conn);
static void (*test_client_input)(struct client_connection *conn);
static void (*test_client_deinit)(struct client_connection *conn);

/*
 * Forward declarations
 */

/* server */
static void
test_server_defaults(struct smtp_server_settings *smtp_set);
static void
test_server_run(const struct smtp_server_settings *smtp_set);

/* client */
static void test_client_run(unsigned int index);

/* test*/
static void test_run_client_server(
	const struct smtp_server_settings *server_set,
	test_server_init_t server_test,
	test_client_init_t client_test,
	unsigned int client_tests_count)
	ATTR_NULL(3);

/*
 * Slow server
 */

/* client */

static void
test_slow_server_input(struct client_connection *conn ATTR_UNUSED)
{
	/* do nothing */
	sleep(10);
}

static void
test_slow_server_connected(struct client_connection *conn)
{
	if (debug)
		i_debug("CONNECTED");

	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n");
}

static void test_client_slow_server(unsigned int index)
{
	test_client_input = test_slow_server_input;
	test_client_connected = test_slow_server_connected;
	test_client_run(index);
}

/* server */

struct _slow_server {
	struct smtp_server_cmd_ctx *cmd;
	struct timeout *to_delay;
	bool serviced:1;
};

static void
test_server_slow_server_destroyed(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
				  struct _slow_server *ctx)
{
	test_assert(ctx->serviced);
	timeout_remove(&ctx->to_delay);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_slow_server_delayed(struct _slow_server *ctx)
{
	struct smtp_server_reply *reply;
	struct smtp_server_cmd_ctx *cmd = ctx->cmd;

	reply = smtp_server_reply_create_ehlo(cmd->cmd);
	smtp_server_reply_ehlo_add(reply, "FROP");

	smtp_server_reply_submit(reply);
	ctx->serviced = TRUE;
}

static int
test_server_slow_server_cmd_helo(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_cmd_helo *data ATTR_UNUSED)
{
	struct _slow_server *ctx;

	if (debug)
		i_debug("HELO");

	ctx = i_new(struct _slow_server, 1);
	ctx->cmd = cmd;

	smtp_server_command_add_hook(cmd->cmd,
				     SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     test_server_slow_server_destroyed, ctx);

	ctx->to_delay = timeout_add(4000,
		test_server_slow_server_delayed, ctx);

	return 0;
}

static void test_server_slow_server
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_cmd_helo = test_server_slow_server_cmd_helo;
	test_server_run(server_set);
}

/* test */

static void test_slow_server(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("slow server");
	test_run_client_server(&smtp_server_set,
		test_server_slow_server,
		test_client_slow_server, 1);
	test_end();
}

/*
 * Slow client
 */

/* client */

static void
test_slow_client_input(struct client_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

static void
test_slow_client_connected(struct client_connection *conn)
{
	if (debug)
		i_debug("CONNECTED");

	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n");
}

static void test_client_slow_client(unsigned int index)
{
	test_client_input = test_slow_client_input;
	test_client_connected = test_slow_client_connected;
	test_client_run(index);
}

/* server */

struct _slow_client {
	struct smtp_server_cmd_ctx *cmd;
	struct timeout *to_delay;
	struct timeout *to_disconnect;
	bool serviced:1;
};

static void
test_server_slow_client_disconnect_timeout(struct _slow_client *ctx)
{
	test_assert(FALSE);

	timeout_remove(&ctx->to_disconnect);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_slow_client_disconnect(void *conn_ctx, const char *reason)
{
	struct server_connection *conn = (struct server_connection *)conn_ctx;
	struct _slow_client *ctx = (struct _slow_client *)conn->context;

	if (debug)
		i_debug("DISCONNECTED: %s", reason);

	timeout_remove(&ctx->to_disconnect);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_slow_client_cmd_destroyed(
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED, struct _slow_client *ctx)
{
	test_assert(ctx->serviced);
	timeout_remove(&ctx->to_delay);
}

static void
test_server_slow_client_delayed(struct _slow_client *ctx)
{
	struct smtp_server_reply *reply;
	struct smtp_server_cmd_ctx *cmd = ctx->cmd;

	timeout_remove(&ctx->to_delay);

	reply = smtp_server_reply_create_ehlo(cmd->cmd);
	smtp_server_reply_ehlo_add(reply, "FROP");

	ctx->to_disconnect = timeout_add(2000,
		test_server_slow_client_disconnect_timeout, ctx);

	smtp_server_reply_submit(reply);
	ctx->serviced = TRUE;
}

static int
test_server_slow_client_cmd_helo(void *conn_ctx,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_cmd_helo *data ATTR_UNUSED)
{
	struct server_connection *conn =
		(struct server_connection *)conn_ctx;
	struct _slow_client *ctx;

	if (debug)
		i_debug("HELO");

	ctx = i_new(struct _slow_client, 1);
	ctx->cmd = cmd;

	conn->context = ctx;

	smtp_server_command_add_hook(cmd->cmd,
				     SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     test_server_slow_client_cmd_destroyed,
				     ctx);

	ctx->to_delay = timeout_add_short(500,
		test_server_slow_client_delayed, ctx);

	return 0;
}

static void test_server_slow_client
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect = test_server_slow_client_disconnect;
	server_callbacks.conn_cmd_helo = test_server_slow_client_cmd_helo;
	test_server_run(server_set);
}

/* test */

static void test_slow_client(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("slow client");
	test_run_client_server(&smtp_server_set,
		test_server_slow_client,
		test_client_slow_client, 1);
	test_end();
}

/*
 * Hanging command payload
 */

/* client */

static void
test_hanging_command_payload_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n"
		"MAIL FROM:<hangman@example.com>\r\n"
		"RCPT TO:<jerry@example.com>\r\n"
		"DATA\r\n"
		"To be continued... or not");
}

static void test_client_hanging_command_payload(unsigned int index)
{
	test_client_connected = test_hanging_command_payload_connected;
	test_client_run(index);
}

/* server */

struct _hanging_command_payload {
	struct istream *payload_input;
	struct io *io;

	bool serviced:1;
};

static void
test_server_hanging_command_payload_trans_free(void *conn_ctx  ATTR_UNUSED,
	struct smtp_server_transaction *trans)
{
	struct _hanging_command_payload *ctx =
		(struct _hanging_command_payload *)trans->context;

	test_assert(!ctx->serviced);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static int
test_server_hanging_command_payload_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data)
{
	if (debug) {
		i_debug("RCPT TO:%s",
			smtp_address_encode(data->path));
	}

	return 1;
}

static int
test_server_hanging_command_payload_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans,
	struct istream *data_input)
{
	struct _hanging_command_payload *ctx;

	if (debug)
		i_debug("DATA");

	ctx = i_new(struct _hanging_command_payload, 1);
	trans->context = ctx;

	ctx->payload_input = data_input;
	return 0;
}

static int
test_server_hanging_command_payload_data_continue(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans)
{
	struct _hanging_command_payload *ctx =
		(struct _hanging_command_payload *)trans->context;
	const unsigned char *data;
	size_t size;
	int ret;


	if (debug)
		i_debug("DATA continue");

	while ((ret=i_stream_read_data(ctx->payload_input,
				       &data, &size, 0)) > 0) {
		i_stream_skip(ctx->payload_input, size);
	}

	if (ret == 0)
		return 0;
	if (ctx->payload_input->stream_errno != 0) {
		i_error("failed to read DATA payload: %s",
			i_stream_get_error(ctx->payload_input));
		return -1;
	}

	i_assert(ctx->payload_input->eof);

	smtp_server_reply(cmd, 250, "2.0.0", "OK");
	ctx->serviced = TRUE;

	i_stream_unref(&ctx->payload_input);
	return 1;
}

static void test_server_hanging_command_payload
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_trans_free =
		test_server_hanging_command_payload_trans_free;

	server_callbacks.conn_cmd_rcpt =
		test_server_hanging_command_payload_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_hanging_command_payload_data_begin;
	server_callbacks.conn_cmd_data_continue =
		test_server_hanging_command_payload_data_continue;
	test_server_run(server_set);
}

/* test */

static void test_hanging_command_payload(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("hanging command payload");
	test_run_client_server(&smtp_server_set,
		test_server_hanging_command_payload,
		test_client_hanging_command_payload, 1);
	test_end();
}

/*
 * Bad command
 */

/* client */

static void
test_bad_command_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO\tfrop\r\n");
}

static void test_client_bad_command(unsigned int index)
{
	test_client_connected = test_bad_command_connected;
	test_client_run(index);
}

/* server */

struct _bad_command {
	struct istream *payload_input;
	struct io *io;

	bool serviced:1;
};

static void
test_server_bad_command_disconnect(void *context ATTR_UNUSED, const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
	io_loop_stop(ioloop);
}

static int
test_server_bad_command_helo(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_helo *data ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static int
test_server_bad_command_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	return 1;
}

static int
test_server_bad_command_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	smtp_server_reply(cmd, 250, "2.0.0", "OK");
	return 1;
}

static void test_server_bad_command
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_bad_command_disconnect;

	server_callbacks.conn_cmd_helo =
		test_server_bad_command_helo;
	server_callbacks.conn_cmd_rcpt =
		test_server_bad_command_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_bad_command_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_bad_command(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("bad command");
	test_run_client_server(&smtp_server_set,
		test_server_bad_command,
		test_client_bad_command, 1);
	test_end();
}

/*
 * Long command
 */

/* client */

static void
test_long_command_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO some.very.very.very.very.very.long.domain\r\n");
}

static void test_client_long_command(unsigned int index)
{
	test_client_connected = test_long_command_connected;
	test_client_run(index);
}

/* server */

struct _long_command {
	struct istream *payload_input;
	struct io *io;

	bool serviced:1;
};

static void
test_server_long_command_disconnect(void *context ATTR_UNUSED, const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
	io_loop_stop(ioloop);
}

static int
test_server_long_command_helo(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_helo *data ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static int
test_server_long_command_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	return 1;
}

static int
test_server_long_command_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	smtp_server_reply(cmd, 250, "2.0.0", "OK");
	return 1;
}

static void test_server_long_command
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_long_command_disconnect;

	server_callbacks.conn_cmd_helo =
		test_server_long_command_helo;
	server_callbacks.conn_cmd_rcpt =
		test_server_long_command_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_long_command_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_long_command(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;
	smtp_server_set.command_limits.max_parameters_size = 32;

	test_begin("long command");
	test_run_client_server(&smtp_server_set,
		test_server_long_command,
		test_client_long_command, 1);
	test_end();
}

/*
 * Big data
 */

/* client */

static void
test_big_data_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n"
		"MAIL FROM:<sender@example.com>\r\n"
		"RCPT TO:<recipient@example.com>\r\n"
		"DATA\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		".\r\n");
}

static void test_client_big_data(unsigned int index)
{
	test_client_connected = test_big_data_connected;
	test_client_run(index);
}

/* server */

struct _big_data {
	struct istream *payload_input;
	struct io *io;
};

static void
test_server_big_data_trans_free(void *conn_ctx  ATTR_UNUSED,
	struct smtp_server_transaction *trans)
{
	struct _big_data *ctx =
		(struct _big_data *)trans->context;

	i_free(ctx);
	io_loop_stop(ioloop);
}

static int
test_server_big_data_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data)
{
	if (debug) {
		i_debug("RCPT TO:%s",
			smtp_address_encode(data->path));
	}
	return 1;
}

static int
test_server_big_data_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans,
	struct istream *data_input)
{
	struct _big_data *ctx;

	if (debug)
		i_debug("DATA");

	ctx = i_new(struct _big_data, 1);
	trans->context = ctx;

	ctx->payload_input = data_input;
	return 0;
}

static int
test_server_big_data_data_continue(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans)
{
	static const size_t max_size = 32;
	struct _big_data *ctx =
		(struct _big_data *)trans->context;
	const unsigned char *data;
	size_t size;
	int ret;


	if (debug)
		i_debug("DATA continue");

	while (ctx->payload_input->v_offset < max_size &&
	       (ret=i_stream_read_data(ctx->payload_input,
				       &data, &size, 0)) > 0) {
		if (ctx->payload_input->v_offset + size > max_size) {
			if (ctx->payload_input->v_offset >= max_size)
				size = 0;
			else
				size = max_size - ctx->payload_input->v_offset;
		}
		i_stream_skip(ctx->payload_input, size);

		if (ctx->payload_input->v_offset >= max_size)
			break;
	}

	if (ctx->payload_input->v_offset >= max_size) {
		smtp_server_reply_early(cmd, 552, "5.3.4",
			"Message too big for system");
		return -1;
	}
		
	if (ret == 0)
		return 0;

	test_assert(FALSE);
	return 1;
}

static void test_server_big_data
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_trans_free =
		test_server_big_data_trans_free;

	server_callbacks.conn_cmd_rcpt =
		test_server_big_data_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_big_data_data_begin;
	server_callbacks.conn_cmd_data_continue =
		test_server_big_data_data_continue;
	test_server_run(server_set);
}

/* test */

static void test_big_data(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;
	smtp_server_set.command_limits.max_data_size = 64;

	test_begin("big_data");
	test_run_client_server(&smtp_server_set,
		test_server_big_data,
		test_client_big_data, 1);
	test_end();
}

/*
 * Bad EHLO
 */

/* client */

static void
test_bad_ehlo_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO \r\n");
}

static void test_client_bad_ehlo(unsigned int index)
{
	test_client_connected = test_bad_ehlo_connected;
	test_client_run(index);
}

/* server */

struct _bad_ehlo {
	struct istream *payload_input;
	struct io *io;

	bool serviced:1;
};

static void
test_server_bad_ehlo_disconnect(void *context ATTR_UNUSED, const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
	io_loop_stop(ioloop);
}

static int
test_server_bad_ehlo_helo(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_helo *data ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static int
test_server_bad_ehlo_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	return 1;
}

static int
test_server_bad_ehlo_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	smtp_server_reply(cmd, 250, "2.0.0", "OK");
	return 1;
}

static void test_server_bad_ehlo
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_bad_ehlo_disconnect;

	server_callbacks.conn_cmd_helo =
		test_server_bad_ehlo_helo;
	server_callbacks.conn_cmd_rcpt =
		test_server_bad_ehlo_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_bad_ehlo_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_bad_ehlo(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("bad EHLO");
	test_run_client_server(&smtp_server_set,
		test_server_bad_ehlo,
		test_client_bad_ehlo, 1);
	test_end();
}

/*
 * Bad MAIL
 */

/* client */

struct _bad_mail_client {
	struct smtp_reply_parser *parser;
	unsigned int reply;

	bool replied:1;
};

static void
test_bad_mail_client_input(struct client_connection *conn)
{
	struct _bad_mail_client *ctx = conn->context;
	struct smtp_reply *reply;
	const char *error;
	int ret;

	while ((ret=smtp_reply_parse_next(ctx->parser, FALSE,
					  &reply, &error)) > 0) {
		if (debug)
			i_debug("REPLY: %s", smtp_reply_log(reply));

		switch (ctx->reply++) {
		case 0: /* greeting */
			i_assert(reply->status == 220);
			break;
		case 1: /* bad command reply */
			switch (client_index) {
			case 0: case 1: case 2: case 3: case 4: case 5: case 6:
				i_assert(reply->status == 501);
				break;
			case 7: case 8:
				i_assert(reply->status == 250);
				break;
			default:
				i_unreached();
			}
			ctx->replied = TRUE;
			io_loop_stop(ioloop);
			connection_disconnect(&conn->conn);
			return;
		default:
			i_unreached();
		}
	}

	i_assert(ret >= 0);
}

static void
test_bad_mail_client_connected(struct client_connection *conn)
{
	struct _bad_mail_client *ctx;

	ctx = p_new(conn->pool, struct _bad_mail_client, 1);
	ctx->parser = smtp_reply_parser_init(conn->conn.input, (size_t)-1);
	conn->context = ctx;

	switch (client_index) {
	case 0:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: <hendrik@example.com>\r\n");
		break;
	case 1:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:hendrik@example.com\r\n");
		break;
	case 2:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: hendrik@example.com\r\n");
		break;
	case 3:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:\r\n");
		break;
	case 4:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: \r\n");
		break;
	case 5:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: BODY=7BIT\r\n");
		break;
	case 6:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: <>\r\n");
		break;
	case 7:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n");
		break;
	case 8:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<>\r\n");
		break;
	default:
		i_unreached();
	}
}

static void
test_bad_mail_client_deinit(struct client_connection *conn)
{
	struct _bad_mail_client *ctx = conn->context;

	i_assert(ctx->replied);
	smtp_reply_parser_deinit(&ctx->parser);
}

static void test_client_bad_mail(unsigned int index)
{
	test_client_input = test_bad_mail_client_input;
	test_client_connected = test_bad_mail_client_connected;
	test_client_deinit = test_bad_mail_client_deinit;
	test_client_run(index);
}

/* server */

static void
test_server_bad_mail_disconnect(void *context ATTR_UNUSED, const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
}

static int
test_server_bad_mail_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static int
test_server_bad_mail_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static void test_server_bad_mail
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_bad_mail_disconnect;

	server_callbacks.conn_cmd_rcpt =
		test_server_bad_mail_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_bad_mail_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_bad_mail(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("bad MAIL");
	test_run_client_server(&smtp_server_set,
		test_server_bad_mail,
		test_client_bad_mail, 9);
	test_end();
}

/*
 * Bad RCPT
 */

/* client */

struct _bad_rcpt_client {
	struct smtp_reply_parser *parser;
	unsigned int reply;

	bool replied:1;
};

static void
test_bad_rcpt_client_input(struct client_connection *conn)
{
	struct _bad_rcpt_client *ctx = conn->context;
	struct smtp_reply *reply;
	const char *error;
	int ret;

	while ((ret=smtp_reply_parse_next(ctx->parser, FALSE,
					  &reply, &error)) > 0) {
		if (debug)
			i_debug("REPLY: %s", smtp_reply_log(reply));

		switch (ctx->reply++) {
		case 0: /* greeting */
			i_assert(reply->status == 220);
			break;
		case 1: /* MAIL FROM */
			i_assert(reply->status == 250);
			break;
		case 2: /* bad command reply */
			switch (client_index) {
			case 0: case 1: case 2: case 3: case 4: case 5:
				i_assert(reply->status == 501);
				break;
			case 6:
				i_assert(reply->status == 250);
				break;
			default:
				i_unreached();
			}
			ctx->replied = TRUE;
			io_loop_stop(ioloop);
			connection_disconnect(&conn->conn);
			return;
		default:
			i_unreached();
		}
	}

	i_assert(ret >= 0);
}

static void
test_bad_rcpt_client_connected(struct client_connection *conn)
{
	struct _bad_rcpt_client *ctx;

	ctx = p_new(conn->pool, struct _bad_rcpt_client, 1);
	ctx->parser = smtp_reply_parser_init(conn->conn.input, (size_t)-1);
	conn->context = ctx;

	switch (client_index) {
	case 0:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: <harrie@example.com>\r\n");
		break;
	case 1:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:harrie@example.com\r\n");
		break;
	case 2:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: harrie@example.com\r\n");
		break;
	case 3:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:\r\n");
		break;
	case 4:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: \r\n");
		break;
	case 5:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: NOTIFY=NEVER\r\n");
		break;
	case 6:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:<harrie@example.com>\r\n");
		break;
	default:
		i_unreached();
	}
}

static void
test_bad_rcpt_client_deinit(struct client_connection *conn)
{
	struct _bad_rcpt_client *ctx = conn->context;

	i_assert(ctx->replied);
	smtp_reply_parser_deinit(&ctx->parser);
}

static void test_client_bad_rcpt(unsigned int index)
{
	test_client_input = test_bad_rcpt_client_input;
	test_client_connected = test_bad_rcpt_client_connected;
	test_client_deinit = test_bad_rcpt_client_deinit;
	test_client_run(index);
}

/* server */

static void
test_server_bad_rcpt_disconnect(void *context ATTR_UNUSED, const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
}

static int
test_server_bad_rcpt_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	return 1;
}

static int
test_server_bad_rcpt_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static void test_server_bad_rcpt
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_bad_rcpt_disconnect;

	server_callbacks.conn_cmd_rcpt =
		test_server_bad_rcpt_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_bad_rcpt_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_bad_rcpt(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("bad RCPT");
	test_run_client_server(&smtp_server_set,
		test_server_bad_rcpt,
		test_client_bad_rcpt, 7);
	test_end();
}

/*
 * MAIL workarounds
 */

/* client */

struct _mail_workarounds_client {
	struct smtp_reply_parser *parser;
	unsigned int reply;

	bool replied:1;
};

static void
test_mail_workarounds_client_input(struct client_connection *conn)
{
	struct _mail_workarounds_client *ctx = conn->context;
	struct smtp_reply *reply;
	const char *error;
	int ret;

	while ((ret=smtp_reply_parse_next(ctx->parser, FALSE,
					  &reply, &error)) > 0) {
		if (debug)
			i_debug("REPLY: %s", smtp_reply_log(reply));

		switch (ctx->reply++) {
		case 0: /* greeting */
			i_assert(reply->status == 220);
			break;
		case 1: /* bad command reply */
			switch (client_index) {
			case 5: case 6: case 7:
				i_assert(reply->status == 501);
				break;
			case 0: case 1: case 2: case 3: case 4: case 8:
			case 9: case 10:
				i_assert(reply->status == 250);
				break;
			default:
				i_unreached();
			}
			ctx->replied = TRUE;
			io_loop_stop(ioloop);
			connection_disconnect(&conn->conn);
			return;
		default:
			i_unreached();
		}
	}

	i_assert(ret >= 0);
}

static void
test_mail_workarounds_client_connected(struct client_connection *conn)
{
	struct _mail_workarounds_client *ctx;

	ctx = p_new(conn->pool, struct _mail_workarounds_client, 1);
	ctx->parser = smtp_reply_parser_init(conn->conn.input, (size_t)-1);
	conn->context = ctx;

	switch (client_index) {
	case 0:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: <hendrik@example.com>\r\n");
		break;
	case 1:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:\t<hendrik@example.com>\r\n");
		break;
	case 2:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:\t <hendrik@example.com>\r\n");
		break;
	case 3:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:hendrik@example.com\r\n");
		break;
	case 4:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: hendrik@example.com\r\n");
		break;
	case 5:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:\r\n");
		break;
	case 6:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: \r\n");
		break;
	case 7:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: BODY=7BIT\r\n");
		break;
	case 8:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM: <>\r\n");
		break;
	case 9:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n");
		break;
	case 10:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<>\r\n");
		break;
	default:
		i_unreached();
	}
}

static void
test_mail_workarounds_client_deinit(struct client_connection *conn)
{
	struct _mail_workarounds_client *ctx = conn->context;

	i_assert(ctx->replied);
	smtp_reply_parser_deinit(&ctx->parser);
}

static void test_client_mail_workarounds(unsigned int index)
{
	test_client_input = test_mail_workarounds_client_input;
	test_client_connected = test_mail_workarounds_client_connected;
	test_client_deinit = test_mail_workarounds_client_deinit;
	test_client_run(index);
}

/* server */

static void
test_server_mail_workarounds_disconnect(void *context ATTR_UNUSED,
					const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
}

static int
test_server_mail_workarounds_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static int
test_server_mail_workarounds_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static void test_server_mail_workarounds
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_mail_workarounds_disconnect;

	server_callbacks.conn_cmd_rcpt =
		test_server_mail_workarounds_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_mail_workarounds_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_mail_workarounds(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.workarounds =
		SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH |
		SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH;
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("MAIL workarounds");
	test_run_client_server(&smtp_server_set,
		test_server_mail_workarounds,
		test_client_mail_workarounds, 11);
	test_end();
}

/*
 * RCPT workarounds
 */

/* client */

struct _rcpt_workarounds_client {
	struct smtp_reply_parser *parser;
	unsigned int reply;

	bool replied:1;
};

static void
test_rcpt_workarounds_client_input(struct client_connection *conn)
{
	struct _rcpt_workarounds_client *ctx = conn->context;
	struct smtp_reply *reply;
	const char *error;
	int ret;

	while ((ret=smtp_reply_parse_next(ctx->parser, FALSE,
					  &reply, &error)) > 0) {
		if (debug)
			i_debug("REPLY: %s", smtp_reply_log(reply));

		switch (ctx->reply++) {
		case 0: /* greeting */
			i_assert(reply->status == 220);
			break;
		case 1: /* MAIL FROM */
			i_assert(reply->status == 250);
			break;
		case 2: /* bad command reply */
			switch (client_index) {
			case 5: case 6: case 7:
				i_assert(reply->status == 501);
				break;
			case 0: case 1: case 2: case 3: case 4: case 8:
				i_assert(reply->status == 250);
				break;
			default:
				i_unreached();
			}
			ctx->replied = TRUE;
			io_loop_stop(ioloop);
			connection_disconnect(&conn->conn);
			return;
		default:
			i_unreached();
		}
	}

	i_assert(ret >= 0);
}

static void
test_rcpt_workarounds_client_connected(struct client_connection *conn)
{
	struct _rcpt_workarounds_client *ctx;

	ctx = p_new(conn->pool, struct _rcpt_workarounds_client, 1);
	ctx->parser = smtp_reply_parser_init(conn->conn.input, (size_t)-1);
	conn->context = ctx;

	switch (client_index) {
	case 0:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: <harrie@example.com>\r\n");
		break;
	case 1:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:\t<harrie@example.com>\r\n");
		break;
	case 2:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:\t <harrie@example.com>\r\n");
		break;
	case 3:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:harrie@example.com\r\n");
		break;
	case 4:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: harrie@example.com\r\n");
		break;
	case 5:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:\r\n");
		break;
	case 6:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: \r\n");
		break;
	case 7:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO: NOTIFY=NEVER\r\n");
		break;
	case 8:
		o_stream_nsend_str(conn->conn.output,
			"MAIL FROM:<hendrik@example.com>\r\n"
			"RCPT TO:<harrie@example.com>\r\n");
		break;
	default:
		i_unreached();
	}
}

static void
test_rcpt_workarounds_client_deinit(struct client_connection *conn)
{
	struct _rcpt_workarounds_client *ctx = conn->context;

	i_assert(ctx->replied);
	smtp_reply_parser_deinit(&ctx->parser);
}

static void test_client_rcpt_workarounds(unsigned int index)
{
	test_client_input = test_rcpt_workarounds_client_input;
	test_client_connected = test_rcpt_workarounds_client_connected;
	test_client_deinit = test_rcpt_workarounds_client_deinit;
	test_client_run(index);
}

/* server */

static void
test_server_rcpt_workarounds_disconnect(void *context ATTR_UNUSED,
					const char *reason)
{
	if (debug)
		i_debug("Disconnect: %s", reason);
}

static int
test_server_rcpt_workarounds_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	return 1;
}

static int
test_server_rcpt_workarounds_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	test_assert(FALSE);
	return 1;
}

static void test_server_rcpt_workarounds
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_disconnect =
		test_server_rcpt_workarounds_disconnect;

	server_callbacks.conn_cmd_rcpt =
		test_server_rcpt_workarounds_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_rcpt_workarounds_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_rcpt_workarounds(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.workarounds =
		SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH |
		SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH;
	smtp_server_set.max_client_idle_time_msecs = 1000;

	test_begin("RCPT workarounds");
	test_run_client_server(&smtp_server_set,
		test_server_rcpt_workarounds,
		test_client_rcpt_workarounds, 9);
	test_end();
}

/*
 * Too many recipients
 */

/* client */

static void
test_too_many_recipients_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n"
		"MAIL FROM:<sender@example.com>\r\n"
		"RCPT TO:<recipient1@example.com>\r\n"
		"RCPT TO:<recipient2@example.com>\r\n"
		"RCPT TO:<recipient3@example.com>\r\n"
		"RCPT TO:<recipient4@example.com>\r\n"
		"RCPT TO:<recipient5@example.com>\r\n"
		"RCPT TO:<recipient6@example.com>\r\n"
		"RCPT TO:<recipient7@example.com>\r\n"
		"RCPT TO:<recipient8@example.com>\r\n"
		"RCPT TO:<recipient9@example.com>\r\n"
		"RCPT TO:<recipient10@example.com>\r\n"
		"RCPT TO:<recipient11@example.com>\r\n"
		"DATA\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		"0123456789ABCDEF0123456789ABCDEF\r\n"
		".\r\n");
}

static void test_client_too_many_recipients(unsigned int index)
{
	test_client_connected = test_too_many_recipients_connected;
	test_client_run(index);
}

/* server */

static void
test_server_too_many_recipients_trans_free(void *conn_ctx  ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static int
test_server_too_many_recipients_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data)
{
	if (debug) {
		i_debug("RCPT TO:%s",
			smtp_address_encode(data->path));
	}
	return 1;
}

static int
test_server_too_many_recipients_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans,
	struct istream *data_input ATTR_UNUSED)
{
	test_assert(array_count(&trans->rcpt_to) == 10);

	smtp_server_reply(cmd, 250, "2.0.0", "OK");
	return 1;
}

static void test_server_too_many_recipients
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_trans_free =
		test_server_too_many_recipients_trans_free;
	server_callbacks.conn_cmd_rcpt =
		test_server_too_many_recipients_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_too_many_recipients_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_too_many_recipients(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.max_client_idle_time_msecs = 1000;
	smtp_server_set.max_recipients = 10;

	test_begin("too many recipients");
	test_run_client_server(&smtp_server_set,
		test_server_too_many_recipients,
		test_client_too_many_recipients, 1);
	test_end();
}

/*
 * DATA without MAIL
 */

/* client */

static void
test_data_no_mail_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n"
		"DATA\r\n"
		".\r\n"
		"RSET\r\n");
}

static void test_client_data_no_mail(unsigned int index)
{
	test_client_connected = test_data_no_mail_connected;
	test_client_run(index);
}

/* server */

static int
test_server_data_no_mail_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	/* not supposed to get here */
	i_assert(FALSE);
	return 1;
}

static int
test_server_data_no_mail_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	/* not supposed to get here */
	i_assert(FALSE);
	return 1;
}

static int
test_server_data_no_mail_rset(void *conn_ctx ATTR_UNUSED,
			      struct smtp_server_cmd_ctx *cmd ATTR_UNUSED)
{
	io_loop_stop(ioloop);
	return 1;
}

static void test_server_data_no_mail
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_cmd_rcpt =
		test_server_data_no_mail_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_data_no_mail_data_begin;
	server_callbacks.conn_cmd_rset =
		test_server_data_no_mail_rset;
	test_server_run(server_set);
}

/* test */

static void test_data_no_mail(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.capabilities =
		SMTP_CAPABILITY_BINARYMIME | SMTP_CAPABILITY_CHUNKING;
	smtp_server_set.max_client_idle_time_msecs = 1000;
	smtp_server_set.max_recipients = 10;

	test_begin("DATA without MAIL");
	test_run_client_server(&smtp_server_set,
		test_server_data_no_mail,
		test_client_data_no_mail, 1);
	test_end();
}

/*
 * DATA without RCPT
 */

/* client */

static void
test_data_no_rcpt_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n"
		"MAIL FROM:<sender@example.com>\r\n"
		"DATA\r\n"
		".\r\n"
		"RSET\r\n");
}

static void test_client_data_no_rcpt(unsigned int index)
{
	test_client_connected = test_data_no_rcpt_connected;
	test_client_run(index);
}

/* server */

static void
test_server_data_no_rcpt_trans_free(void *conn_ctx  ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static int
test_server_data_no_rcpt_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	/* not supposed to get here */
	i_assert(FALSE);
	return 1;
}

static int
test_server_data_no_rcpt_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	/* not supposed to get here */
	i_assert(FALSE);
	return 1;
}

static void test_server_data_no_rcpt
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_trans_free =
		test_server_data_no_rcpt_trans_free;
	server_callbacks.conn_cmd_rcpt =
		test_server_data_no_rcpt_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_data_no_rcpt_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_data_no_rcpt(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.capabilities =
		SMTP_CAPABILITY_BINARYMIME | SMTP_CAPABILITY_CHUNKING;
	smtp_server_set.max_client_idle_time_msecs = 1000;
	smtp_server_set.max_recipients = 10;

	test_begin("DATA without RCPT");
	test_run_client_server(&smtp_server_set,
		test_server_data_no_rcpt,
		test_client_data_no_rcpt, 1);
	test_end();
}

/*
 * DATA with BINARYMIME
 */

/* client */

static void
test_data_binarymime_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"EHLO frop\r\n"
		"MAIL FROM:<sender@example.com> BODY=BINARYMIME\r\n"
		"RCPT TO:<recipient1@example.com>\r\n"
		"DATA\r\n"
		".\r\n"
		"RSET\r\n");
}

static void test_client_data_binarymime(unsigned int index)
{
	test_client_connected = test_data_binarymime_connected;
	test_client_run(index);
}

/* server */

static void
test_server_data_binarymime_trans_free(void *conn_ctx  ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static int
test_server_data_binarymime_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_cmd_rcpt *data)
{
	if (debug) {
		i_debug("RCPT TO:%s",
			smtp_address_encode(data->path));
	}
	return 1;
}

static int
test_server_data_binarymime_data_begin(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_transaction *trans ATTR_UNUSED,
	struct istream *data_input ATTR_UNUSED)
{
	/* not supposed to get here */
	i_assert(FALSE);
	return 1;
}

static void test_server_data_binarymime
(const struct smtp_server_settings *server_set)
{
	server_callbacks.conn_trans_free =
		test_server_data_binarymime_trans_free;
	server_callbacks.conn_cmd_rcpt =
		test_server_data_binarymime_rcpt;
	server_callbacks.conn_cmd_data_begin =
		test_server_data_binarymime_data_begin;
	test_server_run(server_set);
}

/* test */

static void test_data_binarymime(void)
{
	struct smtp_server_settings smtp_server_set;

	test_server_defaults(&smtp_server_set);
	smtp_server_set.capabilities =
		SMTP_CAPABILITY_BINARYMIME | SMTP_CAPABILITY_CHUNKING;
	smtp_server_set.max_client_idle_time_msecs = 1000;
	smtp_server_set.max_recipients = 10;

	test_begin("DATA with BINARYMIME");
	test_run_client_server(&smtp_server_set,
		test_server_data_binarymime,
		test_client_data_binarymime, 1);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_slow_server,
	test_slow_client,
	test_hanging_command_payload,
	test_bad_command,
	test_long_command,
	test_big_data,
	test_bad_ehlo,
	test_bad_mail,
	test_bad_rcpt,
	test_mail_workarounds,
	test_rcpt_workarounds,
	test_too_many_recipients,
	test_data_no_mail,
	test_data_no_rcpt,
	test_data_binarymime,
	NULL
};

/*
 * Test client
 */

/* client connection */

static void
client_connection_input(struct connection *_conn)
{
	struct client_connection *conn = (struct client_connection *)_conn;

	if (test_client_input != NULL)
		test_client_input(conn);
}

static void
client_connection_connected(struct connection *_conn, bool success)
{
	struct client_connection *conn = (struct client_connection *)_conn;

	if (debug)
		i_debug("Client connected");

	if (success && test_client_connected != NULL)
		test_client_connected(conn);
}

static void
client_connection_init(const struct ip_addr *ip, in_port_t port)
{
	struct client_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("client connection", 256);
	conn = p_new(pool, struct client_connection, 1);
	conn->pool = pool;

	connection_init_client_ip(client_conn_list,
		&conn->conn, ip, port);
	(void)connection_client_connect(&conn->conn);
}

static void
server_connection_deinit(struct client_connection **_conn)
{
	struct client_connection *conn = *_conn;

	*_conn = NULL;

	if (test_client_deinit != NULL)
		test_client_deinit(conn);
	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void
client_connection_destroy(struct connection *_conn)
{
	struct client_connection *conn =
		(struct client_connection *)_conn;

	server_connection_deinit(&conn);
}

/* */

static struct connection_settings client_connection_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE
};

static const struct connection_vfuncs client_connection_vfuncs = {
	.destroy = client_connection_destroy,
	.client_connected = client_connection_connected,
	.input = client_connection_input
};

static void test_client_run(unsigned int index)
{
	client_index = index;

	if (debug)
		i_debug("client connecting to %u", bind_port);

	client_conn_list = connection_list_init
		(&client_connection_set, &client_connection_vfuncs);

	client_connection_init(&bind_ip, bind_port);

	io_loop_run(ioloop);

	/* close server socket */
	io_remove(&io_listen);

	connection_list_deinit(&client_conn_list);
}

/*
 * Test server
 */

static void
test_server_defaults(struct smtp_server_settings *smtp_set)
{
	/* server settings */
	i_zero(smtp_set);
	smtp_set->max_client_idle_time_msecs = 5*1000;
	smtp_set->max_pipelined_commands = 1;
	smtp_set->auth_optional = TRUE;
	smtp_set->debug = debug;
}

/* client connection */

static void server_connection_destroy(void *context)
{
	struct server_connection *sconn =
		(struct server_connection *)context;

	if (debug)
		i_debug("Connection destroyed");

	if (--server_pending == 0)
		io_loop_stop(ioloop);
	i_free(sconn);
}

static void
server_connection_accept(void *context ATTR_UNUSED)
{
	struct smtp_server_connection *conn;
	struct server_connection *sconn;
	int fd;

	/* accept new client */
	fd = net_accept(fd_listen, NULL, NULL);
	if (fd == -1)
		return;
	if (fd == -2) {
		i_fatal("test server: accept() failed: %m");
	}

	if (debug)
		i_debug("Accepted connection");

	sconn = i_new(struct server_connection, 1);

	server_callbacks.conn_destroy = server_connection_destroy;

	conn = smtp_server_connection_create(smtp_server, fd, fd,
		NULL, 0, FALSE, NULL, &server_callbacks, sconn);
	smtp_server_connection_start(conn);
}

/* */

static void
test_server_timeout(void *context ATTR_UNUSED)
{
	i_fatal("Server timed out");
}

static void
test_server_run(const struct smtp_server_settings *smtp_set)
{
	struct timeout *to;

	to = timeout_add(SERVER_MAX_TIMEOUT_MSECS,
		test_server_timeout, NULL);

	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, server_connection_accept, (void *)NULL);

	smtp_server = smtp_server_init(smtp_set);

	io_loop_run(ioloop);

	if (debug)
		i_debug("Server finished");

	/* close server socket */
	io_remove(&io_listen);
	timeout_remove(&to);

	smtp_server_deinit(&smtp_server);
}

/*
 * Tests
 */

static int test_open_server_fd(void)
{
	int fd = net_listen(&bind_ip, &bind_port, 128);
	if (debug)
		i_debug("server listening on %u", bind_port);
	if (fd == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), bind_port);
	}
	return fd;
}

static void test_clients_kill_one(unsigned int index, pid_t pid)
{
	(void)kill(pid, SIGKILL);
	if (waitpid(pid, NULL, 0) < 0 &&
	    errno == ECHILD) {
		test_out_quiet(
			t_strdup_printf("client [%u] (pid=%u) still running",
					index, (unsigned int)pid), FALSE);
	}
}

static void test_clients_kill_all(void)
{
	unsigned int i;

	killing_children = TRUE;
	if (client_pids_count > 0) {
		for (i = 0; i < client_pids_count; i++) {
			if (client_pids[i] != (pid_t)-1) {
				test_clients_kill_one(i+1, client_pids[i]);
				client_pids[i] = -1;
			}
		}
	}
	client_pids_count = 0;
	killing_children = FALSE;
}

static void test_run_client_server(
	const struct smtp_server_settings *server_set,
	test_server_init_t server_test,
	test_client_init_t client_test,
	unsigned int client_tests_count)
{
	unsigned int i;

	i_set_failure_prefix("SERVER: ");

	client_pids = NULL;
	client_pids_count = 0;

	fd_listen = test_open_server_fd();

	if (client_tests_count > 0) {
		client_pids = i_new(pid_t, client_tests_count);
		for (i = 0; i < client_tests_count; i++)
			client_pids[i] = (pid_t)-1;
		client_pids_count = client_tests_count;

		for (i = 0; i < client_tests_count; i++) {
			if ((client_pids[i] = fork()) == (pid_t)-1)
				i_fatal("fork() failed: %m");
			if (client_pids[i] == 0) {
				client_pids[i] = (pid_t)-1;
				client_pids_count = 0;
				i_set_failure_prefix("CLIENT[%d]: ", i+1);
				hostpid_init();
				if (debug)
					i_debug("PID=%s", my_pid);
				/* child: client */
				usleep(100000); /* wait a little for server setup */
				i_close_fd(&fd_listen);
				ioloop = io_loop_create();
				client_test(i);
				io_loop_destroy(&ioloop);
				i_free(client_pids);

				if (debug)
					i_debug("Waiting to be killed");
				/* wait for it to be killed; this way, valgrind
				   will not object to this process going away
				   inelegantly. */
				sleep(60);

				exit(1);
			}
		}
		if (debug)
			i_debug("PID=%s", my_pid);
	}

	/* parent: server */

	i_zero(&server_callbacks);

	server_pending = client_tests_count;
	ioloop = io_loop_create();
	server_test(server_set);
	io_loop_destroy(&ioloop);

	i_close_fd(&fd_listen);

	test_clients_kill_all();
	i_free(client_pids);
}

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void
test_signal_handler(int signo)
{
	if (terminating != 0)
		raise(signo);
	terminating = 1;

	/* make sure we don't leave any pesky children alive */
	test_clients_kill_all();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void
test_child_handler(int signo ATTR_UNUSED)
{
	int saved_errno = errno;

	if (killing_children) {
		/* waitpid() is used in test_clients_kill_all() to check
		   whether child was still running. Therefore, we must not
		   wait for it here when that is happening. */
		return;
	}

	while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
	errno = saved_errno;
}

static void test_atexit(void)
{
	test_clients_kill_all();
}

int main(int argc, char *argv[])
{
	int c;

	atexit(test_atexit);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);
	(void)signal(SIGCHLD, test_child_handler);

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	return test_run(test_functions);
}
