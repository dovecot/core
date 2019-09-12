/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-dot.h"
#include "istream-chain.h"
#include "istream-failure-at.h"
#include "ostream.h"
#include "time-util.h"
#include "sleep.h"
#include "connection.h"
#include "test-common.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define CLIENT_PROGRESS_TIMEOUT     10

/*
 * Types
 */

enum server_connection_state {
	SERVER_CONNECTION_STATE_EHLO = 0,
	SERVER_CONNECTION_STATE_MAIL_FROM,
	SERVER_CONNECTION_STATE_RCPT_TO,
	SERVER_CONNECTION_STATE_DATA,
	SERVER_CONNECTION_STATE_FINISH
};

struct server_connection {
	struct connection conn;
	void *context;

	enum server_connection_state state;
	char *file_path;
	struct istream *dot_input;

	pool_t pool;
};

typedef void (*test_server_init_t)(unsigned int index);
typedef bool (*test_client_init_t)
	(const struct smtp_client_settings *client_set);
typedef void (*test_dns_init_t)(void);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t *bind_ports = 0;
static struct ioloop *ioloop;
static bool debug = FALSE;

/* dns */
static pid_t dns_pid = (pid_t)-1;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static pid_t *server_pids = NULL;
static unsigned int server_pids_count = 0;
static struct connection_list *server_conn_list;
static unsigned int server_index;
static void (*test_server_input)(struct server_connection *conn);
static int (*test_server_input_line)(struct server_connection *conn,
	const char *line);
static int (*test_server_input_data)(struct server_connection *conn,
	const unsigned char *data, size_t size);
static int (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);

/* client */
static struct timeout *to_client_progress = NULL;
static struct smtp_client *smtp_client = NULL;

/*
 * Forward declarations
 */

/* server */
static void test_server_run(unsigned int index);
static void
server_connection_deinit(struct server_connection **_conn);

/* client */
static void
test_client_defaults(struct smtp_client_settings *smtp_set);
static void test_client_deinit(void);

/* test*/
static void test_run_client_server(
	const struct smtp_client_settings *client_set,
	test_client_init_t client_test,
	test_server_init_t server_test,
	unsigned int server_tests_count,
	test_dns_init_t dns_test)
	ATTR_NULL(3);

/*
 * Unconfigured SSL
 */

/* server */

static void
test_server_unconfigured_ssl_input(
	struct server_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

static void
test_server_unconfigured_ssl(unsigned int index)
{
	sleep(100);
	test_server_input = test_server_unconfigured_ssl_input;
	test_server_run(index);
}

/* client */

struct _unconfigured_ssl {
	unsigned int count;
};

static void
test_client_unconfigured_ssl_reply(const struct smtp_reply *reply,
	void *context)
{
	struct _unconfigured_ssl *ctx = (struct _unconfigured_ssl *)context;

	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_unconfigured_ssl(const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct _unconfigured_ssl *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _unconfigured_ssl, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "127.0.0.1", bind_ports[0],
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn,
		test_client_unconfigured_ssl_reply, ctx);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "127.0.0.1", bind_ports[0],
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn,
		test_client_unconfigured_ssl_reply, ctx);

	return TRUE;
}

/* test */

static void test_unconfigured_ssl(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("unconfigured ssl");
	test_run_client_server(&smtp_client_set,
		test_client_unconfigured_ssl,
		test_server_unconfigured_ssl, 1, NULL);
	test_end();
}

/*
 * Unconfigured SSL abort
 */

/* server */

static void
test_server_unconfigured_ssl_abort_input(
	struct server_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

static void
test_server_unconfigured_ssl_abort(unsigned int index)
{
	sleep(100);
	test_server_input = test_server_unconfigured_ssl_abort_input;
	test_server_run(index);
}

/* client */

struct _unconfigured_ssl_abort {
	unsigned int count;
};

static void
test_client_unconfigured_ssl_abort_reply1(const struct smtp_reply *reply,
	struct _unconfigured_ssl_abort *ctx ATTR_UNUSED)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_out_quiet("inappropriate callback", FALSE);
}

static void
test_client_unconfigured_ssl_abort_reply2(const struct smtp_reply *reply,
	struct _unconfigured_ssl_abort *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED);

	i_free(ctx);
	io_loop_stop(ioloop);
}

static bool
test_client_unconfigured_ssl_abort(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _unconfigured_ssl_abort *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _unconfigured_ssl_abort, 1);
	ctx->count = 1;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "127.0.0.1", bind_ports[0],
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_unconfigured_ssl_abort_reply1, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);
	smtp_client_command_abort(&scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "127.0.0.1", bind_ports[0],
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_unconfigured_ssl_abort_reply2, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_unconfigured_ssl_abort(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("unconfigured ssl abort");
	test_run_client_server(&smtp_client_set,
		test_client_unconfigured_ssl_abort,
		test_server_unconfigured_ssl_abort, 1, NULL);
	test_end();
}

/*
 * Host lookup failed
 */

/* client */

struct _host_lookup_failed {
	unsigned int count;
};

static void
test_client_host_lookup_failed_reply(const struct smtp_reply *reply,
	struct _host_lookup_failed *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_host_lookup_failed(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _host_lookup_failed *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _host_lookup_failed, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "host.in-addr.arpa", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_host_lookup_failed_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "host.in-addr.arpa", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_host_lookup_failed_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_host_lookup_failed(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("host lookup failed");
	test_run_client_server(&smtp_client_set,
		test_client_host_lookup_failed,
		NULL, 0, NULL);
	test_end();
}

/*
 * Connection refused
 */

/* server */

static void
test_server_connection_refused(unsigned int index ATTR_UNUSED)
{
	i_close_fd(&fd_listen);
}

/* client */

struct _connection_refused {
	unsigned int count;
};

static void
test_client_connection_refused_reply(const struct smtp_reply *reply,
	struct _connection_refused *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_connection_refused(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _connection_refused *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _connection_refused, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_connection_refused_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_connection_refused_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_connection_refused(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("connection refused");
	test_run_client_server(&smtp_client_set,
		test_client_connection_refused,
		test_server_connection_refused, 1, NULL);
	test_end();
}

/*
 * Connection lost prematurely
 */

/* server */

static void
test_connection_lost_prematurely_input(struct server_connection *conn)
{
	const char *line;

	line = i_stream_read_next_line(conn->conn.input);
	if (line == NULL) {
		if (conn->conn.input->eof ||
			conn->conn.input->stream_errno != 0) {
			server_connection_deinit(&conn);
		}
		return;
	}
	server_connection_deinit(&conn);
}

static int
test_connection_lost_prematurely_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"220 testserver ESMTP Testfix (Frop/GNU)\r\n");
	return 1;
}

static void test_server_connection_lost_prematurely(unsigned int index)
{
	test_server_init = test_connection_lost_prematurely_init;
	test_server_input = test_connection_lost_prematurely_input;
	test_server_run(index);
}

/* client */

struct _connection_lost_prematurely {
	unsigned int count;
};

static void
test_client_connection_lost_prematurely_reply(const struct smtp_reply *reply,
	struct _connection_lost_prematurely *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_connection_lost_prematurely(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _connection_lost_prematurely *ctx;

	ctx = i_new(struct _connection_lost_prematurely, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_connection_lost_prematurely_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_connection_lost_prematurely_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_connection_lost_prematurely(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("connection lost prematurely");
	test_run_client_server(&smtp_client_set,
		test_client_connection_lost_prematurely,
		test_server_connection_lost_prematurely, 1, NULL);
	test_end();
}

/*
 * Connection timed out
 */

/* server */

static void test_server_connection_timed_out(unsigned int index ATTR_UNUSED)
{
	sleep(10);
}

/* client */

struct _connection_timed_out {
	unsigned int count;
};

static void
test_client_connection_timed_out_reply(const struct smtp_reply *reply,
	struct _connection_timed_out *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_connection_timed_out(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _connection_timed_out *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _connection_timed_out, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_connection_timed_out_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_connection_timed_out_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_connection_timed_out(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);
	smtp_client_set.connect_timeout_msecs = 1000;

	test_begin("connection timed out");
	test_run_client_server(&smtp_client_set,
		test_client_connection_timed_out,
		test_server_connection_timed_out, 1, NULL);
	test_end();
}

/*
 * Broken payload
 */

/* server */

static int
test_broken_payload_input_line(struct server_connection *conn ATTR_UNUSED,
	const char *line ATTR_UNUSED)
{
	return 0;
}

static void test_server_broken_payload(unsigned int index)
{
	test_server_input_line = test_broken_payload_input_line;
	test_server_run(index);
}

static int
test_broken_payload_chunking_input_line(
	struct server_connection *conn, const char *line ATTR_UNUSED)
{
	if (conn->state == SERVER_CONNECTION_STATE_EHLO) {
		o_stream_nsend_str(conn->conn.output,
			"250-testserver\r\n"
			"250-PIPELINING\r\n"
			"250-CHUNKING\r\n"
			"250-ENHANCEDSTATUSCODES\r\n"
			"250 DSN\r\n");
		return 1;
	}
	return 0;
}

static void test_server_broken_payload_chunking(unsigned int index)
{
	test_server_input_line = test_broken_payload_chunking_input_line;
	test_server_run(index);
}

/* client */

static void
test_client_broken_payload_rcpt_to_cb(const struct smtp_reply *reply,
	void *context ATTR_UNUSED)
{
	test_assert(smtp_reply_is_success(reply));
}

static void
test_client_broken_payload_rcpt_data_cb(const struct smtp_reply *reply,
	void *context ATTR_UNUSED)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_BROKEN_PAYLOAD);
}

static void
test_client_broken_payload_data_cb(const struct smtp_reply *reply,
	void *context ATTR_UNUSED)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_BROKEN_PAYLOAD);
}

static void
test_client_broken_payload_finished(void *context ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static bool
test_client_broken_payload(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_transaction *strans;
	struct istream *input;

	test_expect_errors(2);

	input = i_stream_create_error_str(EIO, "Moehahahaha!!");
	i_stream_set_name(input, "PURE EVIL");

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	strans = smtp_client_transaction_create(sconn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_broken_payload_finished, NULL);
	smtp_client_connection_unref(&sconn);

	smtp_client_transaction_add_rcpt(strans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_broken_payload_rcpt_to_cb,
		test_client_broken_payload_rcpt_data_cb, NULL);
	smtp_client_transaction_send(strans, input,
		test_client_broken_payload_data_cb, NULL);
	i_stream_unref(&input);

	return TRUE;
}

static bool
test_client_broken_payload_later(
	const struct smtp_client_settings *client_set)
{
	static const char *message =
		"From: lucifer@example.com\r\n"
		"To: lostsoul@example.com\r\n"
		"Subject: Moehahaha!\r\n"
		"\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n"
		"Moehahahahahahahahahahahahahahahahahahahahahaha!!\r\n";
	struct smtp_client_connection *sconn;
	struct smtp_client_transaction *strans;
	struct istream *input, *msg_input;

	test_expect_errors(1);

	msg_input = i_stream_create_from_data(message, strlen(message));
	input = i_stream_create_failure_at(msg_input, 666,
					   EIO, "Moehahahaha!!");
	i_stream_unref(&msg_input);
	i_stream_set_name(input, "PURE EVIL");

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	strans = smtp_client_transaction_create(sconn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_broken_payload_finished, NULL);
	smtp_client_connection_unref(&sconn);

	smtp_client_transaction_add_rcpt(strans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_broken_payload_rcpt_to_cb,
		test_client_broken_payload_rcpt_data_cb, NULL);
	smtp_client_transaction_send
		(strans, input, test_client_broken_payload_data_cb, NULL);
	i_stream_unref(&input);

	return TRUE;
}

/* test */

static void test_broken_payload(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);
	smtp_client_set.connect_timeout_msecs = 1000;

	test_begin("broken payload");
	test_run_client_server(&smtp_client_set,
		test_client_broken_payload,
		test_server_broken_payload, 1, NULL);
	test_end();

	test_begin("broken payload (later)");
	test_run_client_server(&smtp_client_set,
		test_client_broken_payload_later,
		test_server_broken_payload, 1, NULL);
	test_end();

	test_begin("broken payload (later, chunking)");
	test_run_client_server(&smtp_client_set,
		test_client_broken_payload_later,
		test_server_broken_payload_chunking, 1, NULL);
	test_end();
}

/*
 * Connection lost
 */

/* server */

static int
test_connection_lost_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	switch (conn->state) {
	case SERVER_CONNECTION_STATE_EHLO:
		if (server_index == 0) {
			conn->state = SERVER_CONNECTION_STATE_MAIL_FROM;
			sleep(1);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_MAIL_FROM:
		if (server_index == 1) {
			conn->state = SERVER_CONNECTION_STATE_RCPT_TO;
			sleep(1);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_RCPT_TO:
		if (server_index == 2) {
			conn->state = SERVER_CONNECTION_STATE_DATA;
			sleep(1);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_DATA:
		if (server_index == 3) {
			conn->state = SERVER_CONNECTION_STATE_FINISH;
			sleep(1);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_FINISH:
		break;
	}
	return 0;
}

static int
test_connection_lost_input_data(struct server_connection *conn,
	const unsigned char *data ATTR_UNUSED, size_t size ATTR_UNUSED)
{
	sleep(1);
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_connection_lost(unsigned int index)
{
	test_server_input_line = test_connection_lost_input_line;
	test_server_input_data = test_connection_lost_input_data;
	test_server_run(index);
}

/* client */

struct _connection_lost {
	unsigned int count;
};

struct _connection_lost_peer {
	struct _connection_lost *context;
	unsigned int index;
};

static void
test_client_connection_lost_rcpt_to_cb(const struct smtp_reply *reply,
	struct _connection_lost_peer *pctx)
{
	if (debug) {
		i_debug("RCPT TO REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);
		break;
	case 1:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);
		break;
	case 2:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);
		break;
	case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_connection_lost_rcpt_data_cb(const struct smtp_reply *reply,
	struct _connection_lost_peer *pctx)
{
	if (debug) {
		i_debug("RCPT DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(FALSE);
		break;
	case 1:
		test_assert(FALSE);
		break;
	case 2:
		test_assert(FALSE);
		break;
	case 3:
		test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);
		break;
	}
}

static void
test_client_connection_lost_data_cb(const struct smtp_reply *reply,
	struct _connection_lost_peer *pctx)
{
	if (debug) {
		i_debug("DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);
}

static void
test_client_connection_lost_finished(struct _connection_lost_peer *pctx)
{
	struct _connection_lost *ctx = pctx->context;

	if (debug)
		i_debug("FINISHED[%u]", pctx->index);
	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
	i_free(pctx);
}

static void
test_client_connection_lost_submit(struct _connection_lost *ctx,
	unsigned int index)
{
	static const char *message =
		"From: stephan@example.com\r\n"
		"To: timo@example.com\r\n"
		"Subject: Frop!\r\n"
		"\r\n"
		"Frop!\r\n";
	struct _connection_lost_peer *pctx;
	struct smtp_client_connection *sconn;
	struct smtp_client_transaction *strans;
	struct istream *input;

	pctx = i_new(struct _connection_lost_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	input = i_stream_create_from_data(message, strlen(message));
	i_stream_set_name(input, "message");

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	strans = smtp_client_transaction_create(sconn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_connection_lost_finished, pctx);
	smtp_client_connection_unref(&sconn);

	smtp_client_transaction_add_rcpt(strans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_connection_lost_rcpt_to_cb,
		test_client_connection_lost_rcpt_data_cb, pctx);
	smtp_client_transaction_send
		(strans, input, test_client_connection_lost_data_cb, pctx);
	i_stream_unref(&input);
}

static bool
test_client_connection_lost(
	const struct smtp_client_settings *client_set)
{
	struct _connection_lost *ctx;
	unsigned int i;

	ctx = i_new(struct _connection_lost, 1);
	ctx->count = 5;

	smtp_client = smtp_client_init(client_set);

	for (i = 0; i < ctx->count; i++)
		test_client_connection_lost_submit(ctx, i);

	return TRUE;
}

/* test */

static void test_connection_lost(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("connection lost");
	test_run_client_server(&smtp_client_set,
		test_client_connection_lost,
		test_server_connection_lost, 5, NULL);
	test_end();
}

/*
 * Unexpected reply
 */

/* server */

static int
test_unexpected_reply_init(struct server_connection *conn)
{
	if (server_index == 5) {
		o_stream_nsend_str(conn->conn.output,
			"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
		o_stream_nsend_str(conn->conn.output,
			"421 testserver Server shutting down for maintenance\r\n");
		sleep(4);
		server_connection_deinit(&conn);
		return 1;
	}
	return 0;
}

static int
test_unexpected_reply_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	switch (conn->state) {
	case SERVER_CONNECTION_STATE_EHLO:
		if (server_index == 4) {
			o_stream_nsend_str(conn->conn.output,
				"250-testserver\r\n"
				"250-PIPELINING\r\n"
				"250-ENHANCEDSTATUSCODES\r\n"
				"250 DSN\r\n");
			o_stream_nsend_str(conn->conn.output,
				"421 testserver Server shutting down for maintenance\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_MAIL_FROM:
		if (server_index == 3) {
			o_stream_nsend_str(conn->conn.output,
				"250 2.1.0 Ok\r\n");
			o_stream_nsend_str(conn->conn.output,
				"421 testserver Server shutting down for maintenance\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_RCPT_TO:
		if (server_index == 2) {
			o_stream_nsend_str(conn->conn.output,
				"250 2.1.5 Ok\r\n");
			o_stream_nsend_str(conn->conn.output,
				"421 testserver Server shutting down for maintenance\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_DATA:
		if (server_index == 1) {
			o_stream_nsend_str(conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			o_stream_nsend_str(conn->conn.output,
				"421 testserver Server shutting down for maintenance\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_FINISH:
		break;
	}
	return 0;
}

static void test_server_unexpected_reply(unsigned int index)
{
	test_server_init = test_unexpected_reply_init;
	test_server_input_line = test_unexpected_reply_input_line;
	test_server_run(index);
}

/* client */

struct _unexpected_reply {
	unsigned int count;
};

struct _unexpected_reply_peer {
	struct _unexpected_reply *context;
	unsigned int index;

	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;
	struct timeout *to;

	bool login_callback:1;
	bool mail_from_callback:1;
	bool rcpt_to_callback:1;
	bool rcpt_data_callback:1;
	bool data_callback:1;
};

static void
test_client_unexpected_reply_login_cb(const struct smtp_reply *reply,
	void *context)
{
	struct _unexpected_reply_peer *pctx =
		(struct _unexpected_reply_peer *)context;

	pctx->login_callback = TRUE;

	if (debug)
		i_debug("LOGIN REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	switch (pctx->index) {
	case 0: case 1: case 2: case 3: case 4:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 5:
		test_assert(reply->status == 421);
		break;
	}
}

static void
test_client_unexpected_reply_mail_from_cb(const struct smtp_reply *reply,
	struct _unexpected_reply_peer *pctx)
{
	if (debug)
		i_debug("MAIL FROM REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->mail_from_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1: case 2: case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 4: case 5:
		test_assert(reply->status == 421);
		break;
	}
}

static void
test_client_unexpected_reply_rcpt_to_cb(const struct smtp_reply *reply,
	struct _unexpected_reply_peer *pctx)
{
	if (debug)
		i_debug("RCPT TO REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->rcpt_to_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1: case 2:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 3: case 4: case 5:
		test_assert(reply->status == 421);
		break;
	}
}

static void
test_client_unexpected_reply_rcpt_data_cb(const struct smtp_reply *reply,
	struct _unexpected_reply_peer *pctx)
{
	if (debug)
		i_debug("RCPT DATA REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->rcpt_data_callback = TRUE;

	switch (pctx->index) {
	case 0:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 1: case 2:
		test_assert(reply->status == 421);
		break;
	case 3: case 4: case 5:
		i_unreached();
	}
}

static void
test_client_unexpected_reply_data_cb(const struct smtp_reply *reply,
	struct _unexpected_reply_peer *pctx)
{
	if (debug)
		i_debug("DATA REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->data_callback = TRUE;

	switch (pctx->index) {
	case 0:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 1: case 2: case 3: case 4: case 5:
		test_assert(reply->status == 421);
		break;
	}
}

static void
test_client_unexpected_reply_finished(struct _unexpected_reply_peer *pctx)
{
	struct _unexpected_reply *ctx = pctx->context;

	if (debug)
		i_debug("FINISHED[%u]", pctx->index);
	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}

	switch (pctx->index) {
	case 0: case 1: case 2:
		test_assert(pctx->mail_from_callback);
		test_assert(pctx->rcpt_to_callback);
		test_assert(pctx->rcpt_data_callback);
		test_assert(pctx->data_callback);
		break;
	case 3: case 4: case 5:
		test_assert(pctx->mail_from_callback);
		test_assert(pctx->rcpt_to_callback);
		test_assert(!pctx->rcpt_data_callback);
		test_assert(pctx->data_callback);
		break;
	}

	pctx->trans = NULL;
	timeout_remove(&pctx->to);
	i_free(pctx);
}

static void
test_client_unexpected_reply_submit2(struct _unexpected_reply_peer *pctx)
{
	struct smtp_client_transaction *strans = pctx->trans;
	static const char *message =
		"From: stephan@example.com\r\n"
		"To: timo@example.com\r\n"
		"Subject: Frop!\r\n"
		"\r\n"
		"Frop!\r\n";
	struct istream *input;

	timeout_remove(&pctx->to);

	input = i_stream_create_from_data(message, strlen(message));
	i_stream_set_name(input, "message");

	smtp_client_transaction_send
		(strans, input, test_client_unexpected_reply_data_cb, pctx);
	i_stream_unref(&input);
}

static void
test_client_unexpected_reply_submit1(struct _unexpected_reply_peer *pctx)
{
	timeout_remove(&pctx->to);

	smtp_client_transaction_add_rcpt(pctx->trans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_unexpected_reply_rcpt_to_cb,
		test_client_unexpected_reply_rcpt_data_cb, pctx);

	pctx->to = timeout_add_short(500,
		test_client_unexpected_reply_submit2, pctx);
}

static void
test_client_unexpected_reply_submit(struct _unexpected_reply *ctx,
	unsigned int index)
{
	struct _unexpected_reply_peer *pctx;

	pctx = i_new(struct _unexpected_reply_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	pctx->conn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	pctx->trans = smtp_client_transaction_create(pctx->conn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_unexpected_reply_finished, pctx);
	smtp_client_connection_connect(pctx->conn,
		test_client_unexpected_reply_login_cb, (void *)pctx);
	smtp_client_transaction_start(pctx->trans,
		test_client_unexpected_reply_mail_from_cb, pctx);
	smtp_client_connection_unref(&pctx->conn);

	pctx->to = timeout_add_short(500,
		test_client_unexpected_reply_submit1, pctx);
}

static bool
test_client_unexpected_reply(
	const struct smtp_client_settings *client_set)
{
	struct _unexpected_reply *ctx;
	unsigned int i;

	ctx = i_new(struct _unexpected_reply, 1);
	ctx->count = 6;

	smtp_client = smtp_client_init(client_set);

	for (i = 0; i < ctx->count; i++)
		test_client_unexpected_reply_submit(ctx, i);

	return TRUE;
}

/* test */

static void test_unexpected_reply(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("unexpected reply");
	test_run_client_server(&smtp_client_set,
		test_client_unexpected_reply,
		test_server_unexpected_reply, 6, NULL);
	test_end();
}

/*
 * Partial reply
 */

/* server */

static int
test_partial_reply_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	if (conn->state == SERVER_CONNECTION_STATE_EHLO)
		return 0;
	o_stream_nsend_str(conn->conn.output,
		"500 Command not");
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_partial_reply(unsigned int index)
{
	test_server_input_line = test_partial_reply_input_line;
	test_server_run(index);
}

/* client */

struct _partial_reply {
	unsigned int count;
};

static void
test_client_partial_reply_reply(const struct smtp_reply *reply,
	struct _partial_reply *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_partial_reply(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _partial_reply *ctx;

	ctx = i_new(struct _partial_reply, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_partial_reply_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_partial_reply_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_partial_reply(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("partial reply");
	test_run_client_server(&smtp_client_set,
		test_client_partial_reply,
		test_server_partial_reply, 1, NULL);
	test_end();
}

/*
 * Premature reply
 */

/* server */

static int
test_premature_reply_init(struct server_connection *conn)
{
	if (server_index == 5) {
		o_stream_nsend_str(conn->conn.output,
			"220 testserver ESMTP Testfix (Debian/GNU)\r\n"
			"250-testserver\r\n"
			"250-PIPELINING\r\n"
			"250-ENHANCEDSTATUSCODES\r\n"
			"250 DSN\r\n");
		sleep(4);
		server_connection_deinit(&conn);
		return 1;
	}
	return 0;
}

static int
test_premature_reply_input_line(struct server_connection *conn, const char *line)
{
	if (debug)
		i_debug("[%u] GOT LINE: %s", server_index, line);
	switch (conn->state) {
	case SERVER_CONNECTION_STATE_EHLO:
		if (debug)
			i_debug("[%u] EHLO", server_index);
		if (server_index == 4) {
			o_stream_nsend_str(conn->conn.output,
				"250-testserver\r\n"
				"250-PIPELINING\r\n"
				"250-ENHANCEDSTATUSCODES\r\n"
				"250 DSN\r\n"
				"250 2.1.0 Ok\r\n");
			conn->state = SERVER_CONNECTION_STATE_MAIL_FROM;
			return 1;
		}
		break;
	case SERVER_CONNECTION_STATE_MAIL_FROM:
		if (server_index == 4) {
			conn->state = SERVER_CONNECTION_STATE_RCPT_TO;
			return 1;
		}
		if (server_index == 3) {
			o_stream_nsend_str(conn->conn.output,
				"250 2.1.0 Ok\r\n"
				"250 2.1.5 Ok\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_RCPT_TO:
		if (server_index == 2) {
			o_stream_nsend_str(conn->conn.output,
				"250 2.1.5 Ok\r\n"
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_DATA:
		if (server_index == 1) {
			o_stream_nsend_str(conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n"
				"250 2.0.0 Ok: queued as 35424ed4af24\r\n");
			sleep(4);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	case SERVER_CONNECTION_STATE_FINISH:
		break;
	}
	return 0;
}

static void test_server_premature_reply(unsigned int index)
{
	test_server_init = test_premature_reply_init;
	test_server_input_line = test_premature_reply_input_line;
	test_server_run(index);
}

/* client */

struct _premature_reply {
	unsigned int count;
};

struct _premature_reply_peer {
	struct _premature_reply *context;
	unsigned int index;

	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;
	struct timeout *to;

	bool login_callback:1;
	bool mail_from_callback:1;
	bool rcpt_to_callback:1;
	bool rcpt_data_callback:1;
	bool data_callback:1;
};

static void
test_client_premature_reply_login_cb(const struct smtp_reply *reply,
	void *context)
{
	struct _premature_reply_peer *pctx =
		(struct _premature_reply_peer *)context;

	pctx->login_callback = TRUE;

	if (debug) {
		i_debug("LOGIN REPLY[%u]: %s", pctx->index,
			smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0: case 1: case 2: case 3: case 4:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 5:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		/* Don't bother continueing with this test. Second try after
		   smtp_client_transaction_start() will have the same result. */
		smtp_client_transaction_abort(pctx->trans);
		break;
	}
}

static void
test_client_premature_reply_mail_from_cb(const struct smtp_reply *reply,
	struct _premature_reply_peer *pctx)
{
	if (debug) {
		i_debug("MAIL FROM REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	pctx->mail_from_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1: case 2: case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 4: case 5:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	}
}

static void
test_client_premature_reply_rcpt_to_cb(const struct smtp_reply *reply,
	struct _premature_reply_peer *pctx)
{
	if (debug) {
		i_debug("RCPT TO REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	pctx->rcpt_to_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1: case 2:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 3:  case 4: case 5:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	}
}

static void
test_client_premature_reply_rcpt_data_cb(const struct smtp_reply *reply,
	struct _premature_reply_peer *pctx)
{
	if (debug) {
		i_debug("RCPT DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	pctx->rcpt_data_callback = TRUE;

	switch (pctx->index) {
	case 0:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 1: case 2:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	case 3: case 4: case 5:
		i_unreached();
	}
}

static void
test_client_premature_reply_data_cb(const struct smtp_reply *reply,
	struct _premature_reply_peer *pctx)
{
	if (debug) {
		i_debug("DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	pctx->data_callback = TRUE;

	switch (pctx->index) {
	case 0:
		test_assert(smtp_reply_is_success(reply));
		break;
	case 1: case 2: case 3: case 4: case 5:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	}
}

static void
test_client_premature_reply_finished(struct _premature_reply_peer *pctx)
{
	struct _premature_reply *ctx = pctx->context;

	if (debug)
		i_debug("FINISHED[%u]", pctx->index);
	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}

	switch (pctx->index) {
	case 0: case 1: case 2:
		test_assert(pctx->mail_from_callback);
		test_assert(pctx->rcpt_to_callback);
		test_assert(pctx->rcpt_data_callback);
		test_assert(pctx->data_callback);
		break;
	case 3: case 4:
		test_assert(pctx->mail_from_callback);
		test_assert(pctx->rcpt_to_callback);
		test_assert(!pctx->rcpt_data_callback);
		test_assert(pctx->data_callback);
		break;
	case 5:
		test_assert(!pctx->mail_from_callback);
		test_assert(!pctx->rcpt_to_callback);
		test_assert(!pctx->rcpt_data_callback);
		test_assert(!pctx->data_callback);
	}

	pctx->trans = NULL;
	timeout_remove(&pctx->to);
	i_free(pctx);
}

static void
test_client_premature_reply_submit3(struct _premature_reply_peer *pctx)
{
	struct smtp_client_transaction *strans = pctx->trans;
	static const char *message =
		"From: stephan@example.com\r\n"
		"To: timo@example.com\r\n"
		"Subject: Frop!\r\n"
		"\r\n"
		"Frop!\r\n";
	struct istream *input;

	timeout_remove(&pctx->to);

	if (debug)
		i_debug("SUBMIT3[%u]", pctx->index);

	input = i_stream_create_from_data(message, strlen(message));
	i_stream_set_name(input, "message");

	smtp_client_transaction_send
		(strans, input, test_client_premature_reply_data_cb, pctx);
	i_stream_unref(&input);
}

static void
test_client_premature_reply_submit2(struct _premature_reply_peer *pctx)
{
	timeout_remove(&pctx->to);

	if (debug)
		i_debug("SUBMIT2[%u]", pctx->index);

	smtp_client_transaction_add_rcpt(pctx->trans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_premature_reply_rcpt_to_cb,
		test_client_premature_reply_rcpt_data_cb, pctx);

	pctx->to = timeout_add_short(500,
		test_client_premature_reply_submit3, pctx);
}


static void
test_client_premature_reply_submit1(struct _premature_reply_peer *pctx)
{
	timeout_remove(&pctx->to);

	if (debug)
		i_debug("SUBMIT1[%u]", pctx->index);

	smtp_client_transaction_start(pctx->trans,
		test_client_premature_reply_mail_from_cb, pctx);

	pctx->to = timeout_add_short(500,
		test_client_premature_reply_submit2, pctx);
}

static void
test_client_premature_reply_submit(struct _premature_reply *ctx,
	unsigned int index)
{
	struct _premature_reply_peer *pctx;
	struct smtp_client_connection *conn;

	pctx = i_new(struct _premature_reply_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	pctx->conn = conn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	pctx->trans = smtp_client_transaction_create(conn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_premature_reply_finished, pctx);
	smtp_client_connection_connect(conn,
		test_client_premature_reply_login_cb, (void *)pctx);
	smtp_client_connection_unref(&conn);

	pctx->to = timeout_add_short(500,
		test_client_premature_reply_submit1, pctx);
}

static bool
test_client_premature_reply(
	const struct smtp_client_settings *client_set)
{
	struct _premature_reply *ctx;
	unsigned int i;

	ctx = i_new(struct _premature_reply, 1);
	ctx->count = 6;

	smtp_client = smtp_client_init(client_set);

	for (i = 0; i < ctx->count; i++)
		test_client_premature_reply_submit(ctx, i);

	return TRUE;
}

/* test */

static void test_premature_reply(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("premature reply");
	test_run_client_server(&smtp_client_set,
		test_client_premature_reply,
		test_server_premature_reply, 6, NULL);
	test_end();
}

/*
 * Early data reply
 */

/* server */

static int
test_early_data_reply_input_line(struct server_connection *conn ATTR_UNUSED,
				 const char *line)
{
	if (debug)
		i_debug("[%u] GOT LINE: %s", server_index, line);

	switch (conn->state) {
	case SERVER_CONNECTION_STATE_DATA:
		break;
	default:
		return 0;
	}

	if ((uintptr_t)conn->context == 0) {
		if (debug)
			i_debug("[%u] REPLIED 354", server_index);
		o_stream_nsend_str(conn->conn.output,
			"354 End data with <CR><LF>.<CR><LF>\r\n");
		conn->context = (void*)1;
		return 1;
	}

	if (server_index == 2 && strcmp(line, ".") == 0) {
		if (debug)
			i_debug("[%u] FINISHED TRANSACTION",
				server_index);
		o_stream_nsend_str(conn->conn.output,
			"250 2.0.0 Ok: queued as 73BDE342129\r\n");
		return 1;
	}

	if ((uintptr_t)conn->context == 5 && server_index < 2) {
		if (debug)
			i_debug("[%u] FINISHED TRANSACTION EARLY",
				server_index);

		if (server_index == 0) {
			o_stream_nsend_str(conn->conn.output,
				"250 2.0.0 Ok: queued as 73BDE342129\r\n");
		} else {
			o_stream_nsend_str(conn->conn.output,
				"452 4.3.1 Mail system full\r\n");
		}
	}
	conn->context = (void*)(((uintptr_t)conn->context) + 1);
	return 1;
}

static void test_server_early_data_reply(unsigned int index)
{
	test_server_input_line = test_early_data_reply_input_line;
	test_server_run(index);
}

/* client */

struct _early_data_reply {
	unsigned int count;
};

struct _early_data_reply_peer {
	struct _early_data_reply *context;
	unsigned int index;

	struct ostream *output;

	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;
	struct timeout *to;

	bool data_callback:1;
};

static void
test_client_early_data_reply_submit1(struct _early_data_reply_peer *pctx);

static void
test_client_early_data_reply_login_cb(const struct smtp_reply *reply,
				      void *context)
{
	struct _early_data_reply_peer *pctx = context;

	if (debug) {
		i_debug("LOGIN REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	test_assert(smtp_reply_is_success(reply));
}

static void
test_client_early_data_reply_mail_from_cb(const struct smtp_reply *reply,
					  struct _early_data_reply_peer *pctx)
{
	if (debug) {
		i_debug("MAIL FROM REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	test_assert(smtp_reply_is_success(reply));
}

static void
test_client_early_data_reply_rcpt_to_cb(const struct smtp_reply *reply,
					struct _early_data_reply_peer *pctx)
{
	if (debug) {
		i_debug("RCPT TO REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	test_assert(smtp_reply_is_success(reply));

	pctx->to = timeout_add_short(1000,
		test_client_early_data_reply_submit1, pctx);
}

static void
test_client_early_data_reply_rcpt_data_cb(const struct smtp_reply *reply,
					  struct _early_data_reply_peer *pctx)
{
	if (debug) {
		i_debug("RCPT DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	case 1:
		test_assert(reply->status == 452);
		break;
	case 2:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_early_data_reply_data_cb(const struct smtp_reply *reply,
				     struct _early_data_reply_peer *pctx)
{
	if (debug) {
		i_debug("DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	pctx->data_callback = TRUE;

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			    SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	case 1:
		test_assert(reply->status == 452);
		break;
	case 2:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_early_data_reply_finished(struct _early_data_reply_peer *pctx)
{
	struct _early_data_reply *ctx = pctx->context;

	if (debug)
		i_debug("FINISHED[%u]", pctx->index);
	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}

	test_assert(pctx->data_callback);

	pctx->trans = NULL;
	timeout_remove(&pctx->to);
	o_stream_destroy(&pctx->output);
	i_free(pctx);
}

static void
test_client_early_data_reply_submit1(struct _early_data_reply_peer *pctx)
{
	if (debug)
		i_debug("FINISH DATA WITH DOT[%u]", pctx->index);

	timeout_remove(&pctx->to);

	if (o_stream_finish(pctx->output) < 0) {
		i_error("Failed to finish output: %s",
			o_stream_get_error(pctx->output));
	}
	o_stream_destroy(&pctx->output);
}

static void
test_client_early_data_reply_submit(struct _early_data_reply *ctx,
				    unsigned int index)
{
	struct _early_data_reply_peer *pctx;
	struct smtp_client_connection *conn;
	static const char *message =
		"From: stephan@example.com\r\n"
		"To: timo@example.com\r\n"
		"Subject: Frop!\r\n"
		"\r\n"
		"Frop!\r\n";
	int pipefd[2];
	struct istream *input;

	pctx = i_new(struct _early_data_reply_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	if (pipe(pipefd) < 0)
		i_fatal("Failed to create pipe: %m");

	fd_set_nonblock(pipefd[0], TRUE);
	fd_set_nonblock(pipefd[1], TRUE);

	input = i_stream_create_fd_autoclose(&pipefd[0], 1024);
	pctx->output = o_stream_create_fd_autoclose(&pipefd[1], 1024);

	pctx->conn = conn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(conn,
		test_client_early_data_reply_login_cb, (void *)pctx);

	pctx->trans = smtp_client_transaction_create(conn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_early_data_reply_finished, pctx);
	smtp_client_transaction_add_rcpt(pctx->trans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_early_data_reply_rcpt_to_cb,
		test_client_early_data_reply_rcpt_data_cb, pctx);
	smtp_client_transaction_start(pctx->trans,
		test_client_early_data_reply_mail_from_cb, pctx);

	smtp_client_transaction_send(
		pctx->trans, input, test_client_early_data_reply_data_cb, pctx);
	i_stream_unref(&input);

	smtp_client_connection_unref(&conn);

	o_stream_nsend(pctx->output, message, strlen(message));
}

static bool
test_client_early_data_reply(
	const struct smtp_client_settings *client_set)
{
	struct _early_data_reply *ctx;
	unsigned int i;

	ctx = i_new(struct _early_data_reply, 1);
	ctx->count = 3;

	smtp_client = smtp_client_init(client_set);

	for (i = 0; i < ctx->count; i++)
		test_client_early_data_reply_submit(ctx, i);

	return TRUE;
}

/* test */

static void test_early_data_reply(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("early data reply");
	test_run_client_server(&smtp_client_set,
		test_client_early_data_reply,
		test_server_early_data_reply, 3, NULL);
	test_end();
}

/*
 * Bad reply
 */

/* server */

static int
test_bad_reply_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	if (conn->state == SERVER_CONNECTION_STATE_EHLO)
		return 0;
	o_stream_nsend_str(conn->conn.output,
		"666 Really bad reply\r\n");
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_bad_reply(unsigned int index)
{
	test_server_input_line = test_bad_reply_input_line;
	test_server_run(index);
}

/* client */

struct _bad_reply {
	unsigned int count;
};

static void
test_client_bad_reply_reply(const struct smtp_reply *reply,
	struct _bad_reply *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_bad_reply(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _bad_reply *ctx;

	ctx = i_new(struct _bad_reply, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_bad_reply_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_bad_reply_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_bad_reply(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("bad reply");
	test_run_client_server(&smtp_client_set,
		test_client_bad_reply,
		test_server_bad_reply, 1, NULL);
	test_end();
}

/*
 * Bad greeting
 */

/* server */

static int
test_bad_greeting_init(struct server_connection *conn)
{
	switch (server_index) {
	case 0:
		o_stream_nsend_str(conn->conn.output,
			"666 Mouhahahaha!!\r\n");
		break;
	case 1:
		o_stream_nsend_str(conn->conn.output,
			"446 Not right now, sorry.\r\n");
		break;
	case 2:
		o_stream_nsend_str(conn->conn.output,
			"233 Gimme all your mail, NOW!!\r\n");
		break;
	}
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_bad_greeting(unsigned int index)
{
	test_server_init = test_bad_greeting_init;
	test_server_run(index);
}

/* client */

struct _bad_greeting {
	unsigned int count;
};

struct _bad_greeting_peer {
	struct _bad_greeting *context;
	unsigned int index;
};

static void
test_client_bad_greeting_reply(const struct smtp_reply *reply,
	struct _bad_greeting_peer *pctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	case 1:
		test_assert(reply->status == 446);
		break;
	case 2:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY);
		break;
	}

	if (--pctx->context->count == 0) {
		i_free(pctx->context);
		io_loop_stop(ioloop);
	}
	i_free(pctx);
}

static void
test_client_bad_greeting_submit(struct _bad_greeting *ctx,
	unsigned int index)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _bad_greeting_peer *pctx;

	pctx = i_new(struct _bad_greeting_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_bad_greeting_reply, pctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);
}

static bool
test_client_bad_greeting(
	const struct smtp_client_settings *client_set)
{
	struct _bad_greeting *ctx;

	ctx = i_new(struct _bad_greeting, 1);
	ctx->count = 3;

	smtp_client = smtp_client_init(client_set);

	test_client_bad_greeting_submit(ctx, 0);
	test_client_bad_greeting_submit(ctx, 1);
	test_client_bad_greeting_submit(ctx, 2);
	return TRUE;
}

/* test */

static void test_bad_greeting(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("bad greeting");
	test_run_client_server(&smtp_client_set,
		test_client_bad_greeting,
		test_server_bad_greeting, 3, NULL);
	test_end();
}

/*
 * Command timeout
 */

/* server */

static int
test_command_timed_out_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	if (conn->state == SERVER_CONNECTION_STATE_EHLO)
		return 0;
	sleep(10);
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_command_timed_out(unsigned int index)
{
	test_server_input_line = test_command_timed_out_input_line;
	test_server_run(index);
}

/* client */

struct _command_timed_out {
	unsigned int count;
};

static void
test_client_command_timed_out_reply(const struct smtp_reply *reply,
	struct _command_timed_out *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_command_timed_out(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _command_timed_out *ctx;

	test_expect_errors(1);

	ctx = i_new(struct _command_timed_out, 1);
	ctx->count = 1;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_command_timed_out_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_command_timed_out(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);
	smtp_client_set.command_timeout_msecs = 1000;

	test_begin("command timed out");
	test_run_client_server(&smtp_client_set,
		test_client_command_timed_out,
		test_server_command_timed_out, 1, NULL);
	test_end();
}

/*
 * Command aborted early
 */

/* server */

static int
test_command_aborted_early_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	if (conn->state == SERVER_CONNECTION_STATE_EHLO)
		return 0;

	sleep(1);
	o_stream_nsend_str(conn->conn.output, "200 OK\r\n");
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_command_aborted_early(unsigned int index)
{
	test_server_input_line = test_command_aborted_early_input_line;
	test_server_run(index);
}

/* client */

struct _command_aborted_early {
	struct smtp_client_command *cmd;
	struct timeout *to;
};

static void
test_client_command_aborted_early_reply(const struct smtp_reply *reply,
	struct _command_aborted_early *ctx ATTR_UNUSED)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	/* abort does not trigger callback */
	test_assert(FALSE);
}

static void
test_client_command_aborted_early_timeout(
	struct _command_aborted_early *ctx)
{
	timeout_remove(&ctx->to);

	if (ctx->cmd != NULL) {
		if (debug)
			i_debug("ABORT");

		/* abort early */
		smtp_client_command_abort(&ctx->cmd);

		/* wait a little for server to actually respond to an
		   already aborted request */
		ctx->to = timeout_add_short(1000,
			test_client_command_aborted_early_timeout, ctx);
	} else {
		if (debug)
			i_debug("FINISHED");

		/* all done */
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_command_aborted_early(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct _command_aborted_early *ctx;

	ctx = i_new(struct _command_aborted_early, 1);

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	ctx->cmd = smtp_client_command_new(sconn, 0,
		test_client_command_aborted_early_reply, ctx);
	smtp_client_command_write(ctx->cmd, "FROP");
	smtp_client_command_submit(ctx->cmd);

	ctx->to = timeout_add_short(500,
		test_client_command_aborted_early_timeout, ctx);

	return TRUE;
}

/* test */

static void test_command_aborted_early(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("command aborted early");
	test_run_client_server(&smtp_client_set,
		test_client_command_aborted_early,
		test_server_command_aborted_early, 1, NULL);
	test_end();
}

/*
 * Client deinit early
 */

/* server */

static int
test_client_deinit_early_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	if (conn->state == SERVER_CONNECTION_STATE_EHLO)
		return 0;

	sleep(1);
	o_stream_nsend_str(conn->conn.output, "200 OK\r\n");
	server_connection_deinit(&conn);
	return -1;
}

static void test_server_client_deinit_early(unsigned int index)
{
	test_server_input_line = test_client_deinit_early_input_line;
	test_server_run(index);
}

/* client */

struct _client_deinit_early {
	struct smtp_client_command *cmd;
	struct timeout *to;
};

static void
test_client_client_deinit_early_reply(const struct smtp_reply *reply,
	struct _client_deinit_early *ctx ATTR_UNUSED)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	/* abort does not trigger callback */
	test_assert(FALSE); 
}

static void
test_client_client_deinit_early_timeout(
	struct _client_deinit_early *ctx)
{
	timeout_remove(&ctx->to);

	/* deinit early */
	smtp_client_deinit(&smtp_client);

	/* all done */
	i_free(ctx);
	io_loop_stop(ioloop);
}

static bool
test_client_client_deinit_early(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct _client_deinit_early *ctx;

	ctx = i_new(struct _client_deinit_early, 1);

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[0],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	ctx->cmd = smtp_client_command_new(sconn, 0,
		test_client_client_deinit_early_reply, ctx);
	smtp_client_command_write(ctx->cmd, "FROP");
	smtp_client_command_submit(ctx->cmd);

	ctx->to = timeout_add_short(500,
		test_client_client_deinit_early_timeout, ctx);

	return TRUE;
}

/* test */

static void test_client_deinit_early(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);


	test_begin("client deinit early");
	test_run_client_server(&smtp_client_set,
		test_client_client_deinit_early,
		test_server_client_deinit_early, 1, NULL);
	test_end();
}

/*
 * DNS service failure
 */

/* client */

struct _dns_service_failure {
	unsigned int count;
};

static void
test_client_dns_service_failure_reply(const struct smtp_reply *reply,
	struct _dns_service_failure *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_dns_service_failure(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _dns_service_failure *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _dns_service_failure, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "host.in-addr.arpa", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_dns_service_failure_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "host.in-addr.arpa", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_dns_service_failure_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_dns_service_failure(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);
	smtp_client_set.dns_client_socket_path = "./frop";

	test_begin("dns service failure");
	test_run_client_server(&smtp_client_set,
		test_client_dns_service_failure,
		NULL, 0, NULL);
	test_end();
}

/*
 * DNS timeout
 */

/* dns */

static void
test_dns_timeout_input(struct server_connection *conn ATTR_UNUSED)
{
	/* hang */
	sleep(100);
	server_connection_deinit(&conn);
}

static void test_dns_dns_timeout(void)
{
	test_server_input = test_dns_timeout_input;
	test_server_run(0);
}

/* client */

struct _dns_timeout {
	unsigned int count;
};

static void
test_client_dns_timeout_reply(const struct smtp_reply *reply,
	struct _dns_timeout *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_dns_timeout(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _dns_timeout *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _dns_timeout, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "example.com", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_dns_timeout_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "example.com", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_dns_timeout_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_dns_timeout(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);
	smtp_client_set.connect_timeout_msecs = 2000;
	smtp_client_set.dns_client_socket_path = "./dns-test";

	test_begin("dns timeout");
	test_run_client_server(&smtp_client_set,
		test_client_dns_timeout, NULL, 0,
		test_dns_dns_timeout);
	test_end();
}

/*
 * DNS lookup failure
 */

/* dns */

static void
test_dns_lookup_failure_input(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		t_strdup_printf("VERSION\tdns\t1\t0\n%d\tFAIL\n", EAI_FAIL));
	server_connection_deinit(&conn);
}

static void test_dns_dns_lookup_failure(void)
{
	test_server_input = test_dns_lookup_failure_input;
	test_server_run(0);
}

/* client */

struct _dns_lookup_failure {
	unsigned int count;
};

static void
test_client_dns_lookup_failure_reply(const struct smtp_reply *reply,
	struct _dns_lookup_failure *ctx)
{
	if (debug)
		i_debug("REPLY: %s", smtp_reply_log(reply));

	test_assert(reply->status == SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_dns_lookup_failure(
	const struct smtp_client_settings *client_set)
{
	struct smtp_client_connection *sconn;
	struct smtp_client_command *scmd;
	struct _dns_lookup_failure *ctx;

	test_expect_errors(2);

	ctx = i_new(struct _dns_lookup_failure, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "example.com", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_dns_lookup_failure_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	sconn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, "example.com", 465,
		SMTP_CLIENT_SSL_MODE_IMMEDIATE, NULL);
	smtp_client_connection_connect(sconn, NULL, NULL);
	scmd = smtp_client_command_new(sconn, 0,
		test_client_dns_lookup_failure_reply, ctx);
	smtp_client_command_write(scmd, "FROP");
	smtp_client_command_submit(scmd);

	return TRUE;
}

/* test */

static void test_dns_lookup_failure(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);
	smtp_client_set.dns_client_socket_path = "./dns-test";

	test_begin("dns lookup failure");
	test_run_client_server(&smtp_client_set,
		test_client_dns_lookup_failure, NULL, 0,
		test_dns_dns_lookup_failure);
	test_end();
}

/*
 * Authentication failed
 */

/* server */

static int
test_authentication_failed_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	switch (conn->state) {
	case SERVER_CONNECTION_STATE_EHLO:
		if (server_index == 1) {
			o_stream_nsend_str(conn->conn.output,
				"250-testserver\r\n"
				"250-PIPELINING\r\n"
				"250-ENHANCEDSTATUSCODES\r\n"
				"250-AUTH PLAIN\r\n"
				"250 DSN\r\n");
			conn->state = SERVER_CONNECTION_STATE_MAIL_FROM;
			return 1;
		}
		break;
	case SERVER_CONNECTION_STATE_MAIL_FROM:
		if (server_index == 1) {
			o_stream_nsend_str(conn->conn.output,
				"535 5.7.8 "
				"Authentication credentials invalid\r\n");
			sleep(10);
			server_connection_deinit(&conn);
			return -1;
		}
		break;
	default:
		break;
	}
	return 0;
}

static void test_server_authentication_failed(unsigned int index)
{
	test_server_input_line = test_authentication_failed_input_line;
	test_server_run(index);
}

/* client */

struct _authentication_failed {
	unsigned int count;
};

struct _authentication_failed_peer {
	struct _authentication_failed *context;
	unsigned int index;

	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;
};

static void
test_client_authentication_failed_login_cb(const struct smtp_reply *reply,
	void *context)
{
	struct _authentication_failed_peer *pctx =
		(struct _authentication_failed_peer *)context;

	if (debug) {
		i_debug("LOGIN REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED);
		break;
	case 1:
		test_assert(reply->status == 535);
		break;
	}
}

static void
test_client_authentication_failed_mail_from_cb(const struct smtp_reply *reply,
	struct _authentication_failed_peer *pctx)
{
	if (debug) {
		i_debug("MAIL FROM REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED);
		break;
	case 1:
		test_assert(reply->status == 535);
		break;
	}
}

static void
test_client_authentication_failed_rcpt_to_cb(const struct smtp_reply *reply,
	struct _authentication_failed_peer *pctx)
{
	if (debug) {
		i_debug("RCPT TO REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED);
		break;
	case 1:
		test_assert(reply->status == 535);
		break;
	}
}

static void
test_client_authentication_failed_rcpt_data_cb(const struct smtp_reply *reply,
	struct _authentication_failed_peer *pctx)
{
	if (debug) {
		i_debug("RCPT DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	test_assert(FALSE);
}

static void
test_client_authentication_failed_data_cb(const struct smtp_reply *reply,
	struct _authentication_failed_peer *pctx)
{
	if (debug) {
		i_debug("DATA REPLY[%u]: %s",
			pctx->index, smtp_reply_log(reply));
	}

	switch (pctx->index) {
	case 0:
		test_assert(reply->status ==
			SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED);
		break;
	case 1:
		test_assert(reply->status == 535);
		break;
	}
}

static void
test_client_authentication_failed_finished(struct _authentication_failed_peer *pctx)
{
	struct _authentication_failed *ctx = pctx->context;

	if (debug)
		i_debug("FINISHED[%u]", pctx->index);
	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}

	pctx->trans = NULL;
	i_free(pctx);
}

static void
test_client_authentication_failed_submit(struct _authentication_failed *ctx,
	unsigned int index)
{
	struct _authentication_failed_peer *pctx;
	struct smtp_client_settings smtp_set;
	static const char *message =
		"From: stephan@example.com\r\n"
		"To: timo@example.com\r\n"
		"Subject: Frop!\r\n"
		"\r\n"
		"Frop!\r\n";
	struct istream *input;

	pctx = i_new(struct _authentication_failed_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	i_zero(&smtp_set);
	smtp_set.username = "peter.wolfsen";
	smtp_set.password = "crybaby";

	pctx->conn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, &smtp_set);
	pctx->trans = smtp_client_transaction_create(pctx->conn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_authentication_failed_finished, pctx);
	smtp_client_connection_connect(pctx->conn,
		test_client_authentication_failed_login_cb, (void *)pctx);
	smtp_client_transaction_start(pctx->trans,
		test_client_authentication_failed_mail_from_cb, pctx);
	smtp_client_connection_unref(&pctx->conn);

	smtp_client_transaction_add_rcpt(pctx->trans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_authentication_failed_rcpt_to_cb,
		test_client_authentication_failed_rcpt_data_cb, pctx);

	input = i_stream_create_from_data(message, strlen(message));
	i_stream_set_name(input, "message");

	smtp_client_transaction_send(pctx->trans,
		input, test_client_authentication_failed_data_cb, pctx);
	i_stream_unref(&input);
}

static bool
test_client_authentication_failed(
	const struct smtp_client_settings *client_set)
{
	struct _authentication_failed *ctx;
	unsigned int i;

	ctx = i_new(struct _authentication_failed, 1);
	ctx->count = 2;

	smtp_client = smtp_client_init(client_set);

	for (i = 0; i < ctx->count; i++)
		test_client_authentication_failed_submit(ctx, i);

	return TRUE;
}

/* test */

static void test_authentication_failed(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("authentication failed");
	test_expect_errors(1);
	test_run_client_server(&smtp_client_set,
		test_client_authentication_failed,
		test_server_authentication_failed, 2, NULL);
	test_end();
}

/*
 * Transaction timeout
 */

/* server */

static int
test_transaction_timeout_input_line(struct server_connection *conn,
	const char *line ATTR_UNUSED)
{
	switch (conn->state) {
	case SERVER_CONNECTION_STATE_EHLO:
		break;
	case SERVER_CONNECTION_STATE_MAIL_FROM:
		if (server_index == 0)
			sleep(20);
		break;
	case SERVER_CONNECTION_STATE_RCPT_TO:
		if (server_index == 1)
			sleep(20);
		break;
	case SERVER_CONNECTION_STATE_DATA:
		if (server_index == 2)
			sleep(20);
		break;
	case SERVER_CONNECTION_STATE_FINISH:
		break;
	}
	return 0;
}

static void test_server_transaction_timeout(unsigned int index)
{
	test_server_input_line = test_transaction_timeout_input_line;
	test_server_run(index);
}

/* client */

struct _transaction_timeout {
	unsigned int count;
};

struct _transaction_timeout_peer {
	struct _transaction_timeout *context;
	unsigned int index;

	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;
	struct timeout *to;

	bool login_callback:1;
	bool mail_from_callback:1;
	bool rcpt_to_callback:1;
	bool rcpt_data_callback:1;
	bool data_callback:1;
};

static void
test_client_transaction_timeout_mail_from_cb(const struct smtp_reply *reply,
	struct _transaction_timeout_peer *pctx)
{
	if (debug)
		i_debug("MAIL FROM REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->mail_from_callback = TRUE;

	switch (pctx->index) {
	case 0:
		test_assert(reply->status == 451);
		break;
	case 1: case 2: case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_transaction_timeout_rcpt_to_cb(const struct smtp_reply *reply,
	struct _transaction_timeout_peer *pctx)
{
	if (debug)
		i_debug("RCPT TO REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->rcpt_to_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1:
		test_assert(reply->status == 451);
		break;
	case 2: case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_transaction_timeout_rcpt_data_cb(const struct smtp_reply *reply,
	struct _transaction_timeout_peer *pctx)
{
	if (debug)
		i_debug("RCPT DATA REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->rcpt_data_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1:
		i_unreached();
	case 2:
		test_assert(reply->status == 451);
		break;
	case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_transaction_timeout_data_cb(const struct smtp_reply *reply,
	struct _transaction_timeout_peer *pctx)
{
	if (debug)
		i_debug("DATA REPLY[%u]: %s", pctx->index, smtp_reply_log(reply));

	pctx->data_callback = TRUE;

	switch (pctx->index) {
	case 0: case 1: case 2:
		test_assert(reply->status == 451);
		break;
	case 3:
		test_assert(smtp_reply_is_success(reply));
		break;
	}
}

static void
test_client_transaction_timeout_finished(struct _transaction_timeout_peer *pctx)
{
	struct _transaction_timeout *ctx = pctx->context;

	if (debug)
		i_debug("FINISHED[%u]", pctx->index);
	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}

	switch (pctx->index) {
	case 0: case 1:
		test_assert(pctx->mail_from_callback);
		test_assert(pctx->rcpt_to_callback);
		test_assert(!pctx->rcpt_data_callback);
		test_assert(pctx->data_callback);
		break;
	case 2: case 3:
		test_assert(pctx->mail_from_callback);
		test_assert(pctx->rcpt_to_callback);
		test_assert(pctx->rcpt_data_callback);
		test_assert(pctx->data_callback);
		break;
	}

	pctx->trans = NULL;
	timeout_remove(&pctx->to);
	i_free(pctx);
}

static void
test_client_transaction_timeout_submit2(struct _transaction_timeout_peer *pctx)
{
	struct smtp_client_transaction *strans = pctx->trans;
	static const char *message =
		"From: stephan@example.com\r\n"
		"To: timo@example.com\r\n"
		"Subject: Frop!\r\n"
		"\r\n"
		"Frop!\r\n";
	struct istream *input;

	timeout_remove(&pctx->to);

	input = i_stream_create_from_data(message, strlen(message));
	i_stream_set_name(input, "message");

	smtp_client_transaction_send
		(strans, input, test_client_transaction_timeout_data_cb, pctx);
	i_stream_unref(&input);
}

static void
test_client_transaction_timeout_submit1(struct _transaction_timeout_peer *pctx)
{
	timeout_remove(&pctx->to);

	smtp_client_transaction_add_rcpt(pctx->trans,
		&((struct smtp_address){.localpart = "rcpt",
					.domain = "example.com"}), NULL,
		test_client_transaction_timeout_rcpt_to_cb,
		test_client_transaction_timeout_rcpt_data_cb, pctx);

	pctx->to = timeout_add_short(500,
		test_client_transaction_timeout_submit2, pctx);
}

static void
test_client_transaction_timeout_submit(struct _transaction_timeout *ctx,
	unsigned int index)
{
	struct _transaction_timeout_peer *pctx;

	pctx = i_new(struct _transaction_timeout_peer, 1);
	pctx->context = ctx;
	pctx->index = index;

	pctx->conn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, net_ip2addr(&bind_ip), bind_ports[index],
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	pctx->trans = smtp_client_transaction_create(pctx->conn,
		&((struct smtp_address){.localpart = "sender",
					.domain = "example.com"}), NULL, 0,
		test_client_transaction_timeout_finished, pctx);
	smtp_client_transaction_set_timeout(pctx->trans, 1000);
	smtp_client_transaction_start(pctx->trans,
		test_client_transaction_timeout_mail_from_cb, pctx);
	smtp_client_connection_unref(&pctx->conn);

	pctx->to = timeout_add_short(500,
		test_client_transaction_timeout_submit1, pctx);
}

static bool
test_client_transaction_timeout(
	const struct smtp_client_settings *client_set)
{
	struct _transaction_timeout *ctx;
	unsigned int i;

	ctx = i_new(struct _transaction_timeout, 1);
	ctx->count = 4;

	smtp_client = smtp_client_init(client_set);

	for (i = 0; i < ctx->count; i++)
		test_client_transaction_timeout_submit(ctx, i);

	return TRUE;
}

/* test */

static void test_transaction_timeout(void)
{
	struct smtp_client_settings smtp_client_set;

	test_client_defaults(&smtp_client_set);

	test_begin("transaction timeout");
	test_run_client_server(&smtp_client_set,
		test_client_transaction_timeout,
		test_server_transaction_timeout, 6, NULL);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_unconfigured_ssl,
	test_unconfigured_ssl_abort,
	test_host_lookup_failed,
	test_connection_refused,
	test_connection_lost_prematurely,
	test_connection_timed_out,
	test_broken_payload,
	test_connection_lost,
	test_unexpected_reply,
	test_premature_reply,
	test_early_data_reply,
	test_partial_reply,
	test_bad_reply,
	test_bad_greeting,
	test_command_timed_out,
	test_command_aborted_early,
	test_client_deinit_early,
	test_dns_service_failure,
	test_dns_timeout,
	test_dns_lookup_failure,
	test_authentication_failed,
	test_transaction_timeout,
	NULL
};

/*
 * Test client
 */

static void
test_client_defaults(struct smtp_client_settings *smtp_set)
{
	/* client settings */
	i_zero(smtp_set);
	smtp_set->my_hostname = "frop.example.com";
	smtp_set->debug = debug;
}

static void
test_client_progress_timeout(void *context ATTR_UNUSED)
{
	/* Terminate test due to lack of progress */
	test_assert(FALSE);
	timeout_remove(&to_client_progress);
	io_loop_stop(current_ioloop);
}

static bool
test_client_init(test_client_init_t client_test,
		 const struct smtp_client_settings *client_set)
{
	i_assert(client_test != NULL);
	if (!client_test(client_set))
		return FALSE;

	to_client_progress = timeout_add(CLIENT_PROGRESS_TIMEOUT*1000,
		test_client_progress_timeout, NULL);

	return TRUE;
}

static void test_client_deinit(void)
{
	timeout_remove(&to_client_progress);

	if (smtp_client != NULL)
		smtp_client_deinit(&smtp_client);
}

static void
test_client_run(test_client_init_t client_test,
		const struct smtp_client_settings *client_set)
{
	if (test_client_init(client_test, client_set))
		io_loop_run(ioloop);
	test_client_deinit();
}

/*
 * Test server
 */

/* client connection */

static void
server_connection_input(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;
	const char *line;
	int ret;

	if (test_server_input != NULL) {
		test_server_input(conn);
		return;
	}

	for (;;) {
		if (conn->state == SERVER_CONNECTION_STATE_FINISH) {
			const unsigned char *data;
			size_t size;
			int ret;

			if (conn->dot_input == NULL)
				conn->dot_input = i_stream_create_dot(conn->conn.input, TRUE);
			while ((ret=i_stream_read_more(conn->dot_input,
				&data, &size)) > 0) {
				if (test_server_input_data != NULL) {
					if (test_server_input_data(conn, data, size) < 0)
						return;
				}
				i_stream_skip(conn->dot_input, size);
			}

			if (ret == 0)
				return;
			if (conn->dot_input->stream_errno != 0) {
				i_error("Failed to read message payload: %s",
					i_stream_get_error(conn->dot_input));
				server_connection_deinit(&conn);
				return;
			}

			o_stream_nsend_str(conn->conn.output,
				"250 2.0.0 Ok: queued as 73BDE342129\r\n");
			conn->state = SERVER_CONNECTION_STATE_MAIL_FROM;
			continue;
		}

		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof ||
				conn->conn.input->stream_errno != 0)
				server_connection_deinit(&conn);
			return;
		}

		if (test_server_input_line != NULL) {
			if ((ret=test_server_input_line(conn, line)) < 0)
				return;
			if (ret > 0)
				continue;
		}

		switch (conn->state) {
		case SERVER_CONNECTION_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
				"250-testserver\r\n"
				"250-PIPELINING\r\n"
				"250-ENHANCEDSTATUSCODES\r\n"
				"250 DSN\r\n");
			conn->state = SERVER_CONNECTION_STATE_MAIL_FROM;
			return;
		case SERVER_CONNECTION_STATE_MAIL_FROM:
			if (str_begins(line, "AUTH ")) {
				o_stream_nsend_str(conn->conn.output,
					"235 2.7.0 "
					"Authentication successful\r\n");
				continue;
			}
			o_stream_nsend_str(conn->conn.output,
				"250 2.1.0 Ok\r\n");
			conn->state = SERVER_CONNECTION_STATE_RCPT_TO;
			continue;
		case SERVER_CONNECTION_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
				"250 2.1.5 Ok\r\n");
			conn->state = SERVER_CONNECTION_STATE_DATA;
			continue;
		case SERVER_CONNECTION_STATE_DATA:
			o_stream_nsend_str(conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			conn->state = SERVER_CONNECTION_STATE_FINISH;
			continue;
		case SERVER_CONNECTION_STATE_FINISH:
			break;
		}
		i_unreached();
	}
}

static void
server_connection_init(int fd)
{
	struct server_connection *conn;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("server connection", 256);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;

	connection_init_server
		(server_conn_list, &conn->conn, "server connection", fd, fd);

	if (test_server_init != NULL) {
		if (test_server_init(conn) != 0)
			return;
	}

	if (test_server_input == NULL) {
		o_stream_nsend_str(conn->conn.output,
			"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
	}
}

static void
server_connection_deinit(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;

	*_conn = NULL;

	if (test_server_deinit != NULL)
		test_server_deinit(conn);

	i_stream_unref(&conn->dot_input);

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void
server_connection_destroy(struct connection *_conn)
{
	struct server_connection *conn =
		(struct server_connection *)_conn;

	server_connection_deinit(&conn);
}

static void
server_connection_accept(void *context ATTR_UNUSED)
{
	int fd;

	/* accept new client */
	fd = net_accept(fd_listen, NULL, NULL);
	if (fd == -1)
		return;
	if (fd == -2) {
		i_fatal("test server: accept() failed: %m");
	}

	server_connection_init(fd);
}

/* */

static struct connection_settings server_connection_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs server_connection_vfuncs = {
	.destroy = server_connection_destroy,
	.input = server_connection_input
};

static void test_server_run(unsigned int index)
{
	server_index = index;

	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, server_connection_accept, NULL);

	server_conn_list = connection_list_init
		(&server_connection_set, &server_connection_vfuncs);

	io_loop_run(ioloop);

	/* close server socket */
	io_remove(&io_listen);

	connection_list_deinit(&server_conn_list);
}

/*
 * Tests
 */

static int test_open_server_fd(in_port_t *bind_port)
{
	int fd = net_listen(&bind_ip, bind_port, 128);
	if (debug)
		i_debug("server listening on %u", *bind_port);
	if (fd == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), *bind_port);
	}
	return fd;
}

static void test_servers_kill_all(void)
{
	unsigned int i;

	if (server_pids_count > 0) {
		for (i = 0; i < server_pids_count; i++) {
			if (server_pids[i] != (pid_t)-1) {
				(void)kill(server_pids[i], SIGKILL);
				(void)waitpid(server_pids[i], NULL, 0);
				server_pids[i] = -1;
			}
		}
	}
	server_pids_count = 0;

	if (dns_pid != (pid_t)-1) {
		(void)kill(dns_pid, SIGKILL);
		(void)waitpid(dns_pid, NULL, 0);
		dns_pid = (pid_t)-1;
	}
}

static void test_run_client_server(
	const struct smtp_client_settings *client_set,
	test_client_init_t client_test,
	test_server_init_t server_test,
	unsigned int server_tests_count,
	test_dns_init_t dns_test)
{
	unsigned int i;

	server_pids = NULL;
	server_pids_count = 0;

	if (server_tests_count > 0) {
		int fds[server_tests_count];

		bind_ports = i_new(in_port_t, server_tests_count);

		server_pids = i_new(pid_t, server_tests_count);
		for (i = 0; i < server_tests_count; i++)
			server_pids[i] = (pid_t)-1;
		server_pids_count = server_tests_count;

		for (i = 0; i < server_tests_count; i++)
			fds[i] = test_open_server_fd(&bind_ports[i]);

		for (i = 0; i < server_tests_count; i++) {
			fd_listen = fds[i];
			if ((server_pids[i] = fork()) == (pid_t)-1)
				i_fatal("fork() failed: %m");
			if (server_pids[i] == 0) {
				lib_signals_ignore(SIGPIPE, TRUE);
				server_pids[i] = (pid_t)-1;
				server_pids_count = 0;
				hostpid_init();
				if (debug)
					i_debug("server[%d]: PID=%s", i+1, my_pid);
				/* child: server */
				ioloop = io_loop_create();
				server_test(i);
				io_loop_destroy(&ioloop);
				i_close_fd(&fd_listen);
				i_free(bind_ports);
				i_free(server_pids);
				/* wait for it to be killed; this way, valgrind will not
				   object to this process going away inelegantly. */
				sleep(60);
				exit(1);
			}
			i_close_fd(&fd_listen);
		}
		if (debug)
			i_debug("client: PID=%s", my_pid);
	}

	if (dns_test != NULL) {
		int fd;

		i_unlink_if_exists("./dns-test");
		fd = net_listen_unix("./dns-test", 128);
		if (fd == -1) {
			i_fatal("listen(./dns-test) failed: %m");
		}

		fd_listen = fd;
		if ((dns_pid = fork()) == (pid_t)-1)
			i_fatal("fork() failed: %m");
		if (dns_pid == 0) {
			lib_signals_ignore(SIGPIPE, TRUE);
			dns_pid = (pid_t)-1;
			hostpid_init();
			if (debug)
				i_debug("dns server: PID=%s", my_pid);
			/* child: server */
			ioloop = io_loop_create();
			dns_test();
			io_loop_destroy(&ioloop);
			i_close_fd(&fd_listen);
			/* wait for it to be killed; this way, valgrind will not
			   object to this process going away inelegantly. */
			sleep(60);
			exit(1);
		}
		i_close_fd(&fd_listen);
	}

	/* parent: client */

	i_sleep_msecs(100); /* wait a little for server setup */

	lib_signals_ignore(SIGPIPE, TRUE);
	ioloop = io_loop_create();
	test_client_run(client_test, client_set);
	io_loop_destroy(&ioloop);

	test_servers_kill_all();
	i_free(server_pids);
	i_free(bind_ports);

	i_unlink_if_exists("./dns-test");
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
	test_servers_kill_all();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_servers_kill_all();
}

int main(int argc, char *argv[])
{
	int c;

	atexit(test_atexit);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);

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
