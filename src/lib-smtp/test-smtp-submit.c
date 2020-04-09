/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-chain.h"
#include "ostream.h"
#include "time-util.h"
#include "sleep.h"
#include "unlink-directory.h"
#include "write-full.h"
#include "connection.h"
#include "master-service.h"
#include "istream-dot.h"
#include "test-common.h"

#include "smtp-address.h"
#include "smtp-submit.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

static const char *test_message1 =
	"Subject: Test message\r\n"
	"To: rcpt@example.com\r\n"
	"From: sender@example.com\r\n"
	"\r\n"
	"Test message\r\n";
static const char *test_message2 =
	"Subject: Test message\r\n"
	"To: rcpt@example.com\r\n"
	"From: sender@example.com\r\n"
	"\r\n"
	"Test message Test message Test message Test message Test message\r\n"
	"Test message Test message Test message Test message Test message\r\n"
	"Test message Test message Test message Test message Test message\r\n"
	"Test message Test message Test message Test message Test message\r\n"
	"Test message Test message Test message Test message Test message\r\n"
	"Test message Test message Test message Test message Test message\r\n";

/*
 * Types
 */

struct server_connection {
	struct connection conn;

	void *context;

	pool_t pool;
};

typedef void (*test_server_init_t)(unsigned int index);
typedef bool
(*test_client_init_t)(const struct smtp_submit_settings *submit_set);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t *bind_ports = NULL;
static struct ioloop *ioloop;
static bool debug = FALSE;
static char *tmp_dir = NULL;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static pid_t *server_pids = NULL;
static in_port_t server_port = 0;
static unsigned int server_pids_count = 0;
static struct connection_list *server_conn_list;
static unsigned int server_index;
static void (*test_server_input)(struct server_connection *conn);
static void (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);

/* client */

/*
 * Forward declarations
 */

/* server */
static void test_server_run(unsigned int index);
static void server_connection_deinit(struct server_connection **_conn);

/* client */
static void
test_client_defaults(struct smtp_submit_settings *smtp_set);
static void test_client_deinit(void);

static int
test_client_smtp_send_simple(const struct smtp_submit_settings *smtp_set,
			     const char *message, const char *host,
			     const char **error_r);
static int
test_client_smtp_send_simple_port(const struct smtp_submit_settings *smtp_set,
				  const char *message, unsigned int port,
				  const char **error_r);

/* test*/
static const char *test_tmp_dir_get(void);

static void test_message_delivery(const char *message, const char *file);

static void
test_run_client_server(const struct smtp_submit_settings *submit_set,
		       test_client_init_t client_test,
		       test_server_init_t server_test,
		       unsigned int server_tests_count) ATTR_NULL(3);

/*
 * Host lookup failed
 */

/* client */

static bool
test_client_host_lookup_failed(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple(submit_set, test_message1,
					   "host.invalid", &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	return FALSE;
}

/* test */

static void test_host_lookup_failed(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("host lookup failed");
	test_expect_errors(1);
	test_run_client_server(&smtp_submit_set,
			       test_client_host_lookup_failed, NULL, 0);
	test_end();
}

/*
 * Connection refused
 */

/* server */

static void test_server_connection_refused(unsigned int index ATTR_UNUSED)
{
	i_close_fd(&fd_listen);
}

/* client */

static bool
test_client_connection_refused(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	return FALSE;
}

/* test */

static void test_connection_refused(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("connection refused");
	test_expect_errors(1);
	test_run_client_server(&smtp_submit_set,
			       test_client_connection_refused,
			       test_server_connection_refused, 1);
	test_end();
}

/*
 * Connection timed out
 */

/* server */

static void test_connection_timed_out_input(struct server_connection *conn)
{
	i_sleep_intr_secs(10);
	server_connection_deinit(&conn);
}

static void test_server_connection_timed_out(unsigned int index)
{
	test_server_input = test_connection_timed_out_input;
	test_server_run(index);
}
/* client */

static bool
test_client_connection_timed_out(const struct smtp_submit_settings *submit_set)
{
	time_t time;
	const char *error = NULL;
	int ret;

	io_loop_time_refresh();
	time = ioloop_time;
	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	io_loop_time_refresh();
	test_out("timeout", (ioloop_time - time) < 5);

	return FALSE;
}

/* test */

static void test_connection_timed_out(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 1;

	test_begin("connection timed out");
	test_expect_errors(1);
	test_run_client_server(&smtp_submit_set,
			       test_client_connection_timed_out,
			       test_server_connection_timed_out, 1);
	test_end();
}

/*
 * Bad greeting
 */

/* server */

static void test_bad_greeting_input(struct server_connection *conn)
{
	server_connection_deinit(&conn);
}

static void test_bad_greeting_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
			   "554 No SMTP service here.\r\n");
}

static void test_server_bad_greeting(unsigned int index)
{
	test_server_init = test_bad_greeting_init;
	test_server_input = test_bad_greeting_input;
	test_server_run(index);
}

/* client */

static bool
test_client_bad_greeting(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret == 0)", ret == 0, error);

	return FALSE;
}

/* test */

static void test_bad_greeting(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("bad greeting");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_bad_greeting,
			       test_server_bad_greeting, 1);
	test_end();
}

/*
 * Denied HELO
 */

/* server */

static void test_denied_helo_input(struct server_connection *conn)
{
	const char *line;

	line = i_stream_read_next_line(conn->conn.input);
	if (line == NULL) {
		if (conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}
	o_stream_nsend_str(conn->conn.output,
			   "550 Command rejected for testing reasons\r\n");
	server_connection_deinit(&conn);
}

static void test_denied_helo_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
			   "220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_denied_helo(unsigned int index)
{
	test_server_init = test_denied_helo_init;
	test_server_input = test_denied_helo_input;
	test_server_run(index);
}

/* client */

static bool
test_client_denied_helo(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set,
		test_message1, bind_ports[0], &error);
	test_out_reason("run (ret == 0)", ret == 0, error);

	return FALSE;
}

/* test */

static void test_denied_helo(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("denied helo");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_denied_helo,
			       test_server_denied_helo, 1);
	test_end();
}

/*
 * Disconnect HELO
 */

/* server */

static void test_disconnect_helo_input(struct server_connection *conn)
{
	const char *line;

	line = i_stream_read_next_line(conn->conn.input);
	if (line == NULL) {
		if (conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}
	server_connection_deinit(&conn);
}

static void test_disconnect_helo_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
			   "220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_disconnect_helo(unsigned int index)
{
	test_server_init = test_disconnect_helo_init;
	test_server_input = test_disconnect_helo_input;
	test_server_run(index);
}

/* client */

static bool
test_client_disconnect_helo(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	return FALSE;
}

/* test */

static void test_disconnect_helo(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("disconnect helo");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_disconnect_helo,
			       test_server_disconnect_helo, 1);
	test_end();
}

/*
 * Denied MAIL
 */

/* server */

enum _denied_mail_state {
	DENIED_MAIL_STATE_EHLO = 0,
	DENIED_MAIL_STATE_MAIL_FROM
};

struct _denied_mail_server {
	enum _denied_mail_state state;
};

static void test_denied_mail_input(struct server_connection *conn)
{
	struct _denied_mail_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _denied_mail_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _denied_mail_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DENIED_MAIL_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DENIED_MAIL_STATE_MAIL_FROM;
			return;
		case DENIED_MAIL_STATE_MAIL_FROM:
			o_stream_nsend_str(
				conn->conn.output,"453 4.3.2 "
				"Incapable of accepting messages at this time.\r\n");
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_denied_mail_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
			   "220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_denied_mail(unsigned int index)
{
	test_server_init = test_denied_mail_init;
	test_server_input = test_denied_mail_input;
	test_server_run(index);
}

/* client */

static bool
test_client_denied_mail(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	return FALSE;
}

/* test */

static void test_denied_mail(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("denied mail");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_denied_mail,
			       test_server_denied_mail, 1);
	test_end();
}

/*
 * Denied RCPT
 */

/* server */

enum _denied_rcpt_state {
	DENIED_RCPT_STATE_EHLO = 0,
	DENIED_RCPT_STATE_MAIL_FROM,
	DENIED_RCPT_STATE_RCPT_TO
};

struct _denied_rcpt_server {
	enum _denied_rcpt_state state;
};

static void test_denied_rcpt_input(struct server_connection *conn)
{
	struct _denied_rcpt_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _denied_rcpt_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _denied_rcpt_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DENIED_RCPT_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DENIED_RCPT_STATE_MAIL_FROM;
			return;
		case DENIED_RCPT_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = DENIED_RCPT_STATE_RCPT_TO;
			continue;
		case DENIED_RCPT_STATE_RCPT_TO:
			o_stream_nsend_str(
				conn->conn.output, "550 5.4.3 "
				"Directory server failure\r\n");
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_denied_rcpt_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_denied_rcpt(unsigned int index)
{
	test_server_init = test_denied_rcpt_init;
	test_server_input = test_denied_rcpt_input;
	test_server_run(index);
}

/* client */

static bool
test_client_denied_rcpt(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret == 0)", ret == 0, error);

	return FALSE;
}

/* test */

static void test_denied_rcpt(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("denied rcpt");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_denied_rcpt,
			       test_server_denied_rcpt, 1);
	test_end();
}

/*
 * Denied second RCPT
 */

/* server */

enum _denied_second_rcpt_state {
	DENIED_SECOND_RCPT_STATE_EHLO = 0,
	DENIED_SECOND_RCPT_STATE_MAIL_FROM,
	DENIED_SECOND_RCPT_STATE_RCPT_TO,
	DENIED_SECOND_RCPT_STATE_RCPT_TO2
};

struct _denied_second_rcpt_server {
	enum _denied_second_rcpt_state state;
};

static void test_denied_second_rcpt_input(struct server_connection *conn)
{
	struct _denied_second_rcpt_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _denied_second_rcpt_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _denied_second_rcpt_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DENIED_SECOND_RCPT_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DENIED_SECOND_RCPT_STATE_MAIL_FROM;
			return;
		case DENIED_SECOND_RCPT_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = DENIED_SECOND_RCPT_STATE_RCPT_TO;
			continue;
		case DENIED_SECOND_RCPT_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.5 Ok\r\n");
			ctx->state = DENIED_SECOND_RCPT_STATE_RCPT_TO2;
			continue;
		case DENIED_SECOND_RCPT_STATE_RCPT_TO2:
			o_stream_nsend_str(conn->conn.output, "550 5.4.3 "
					   "Directory server failure\r\n");
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_denied_second_rcpt_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_denied_second_rcpt(unsigned int index)
{
	test_server_init = test_denied_second_rcpt_init;
	test_server_input = test_denied_second_rcpt_input;
	test_server_run(index);
}

/* client */

static void test_smtp_submit_input_init(struct smtp_submit_input *smtp_input_r)
{
	i_zero(smtp_input_r);
	smtp_input_r->allow_root = TRUE;
}

static bool
test_client_denied_second_rcpt(const struct smtp_submit_settings *submit_set)
{
	struct smtp_submit *smtp_submit;
	struct smtp_submit_input smtp_input;
	struct smtp_submit_settings smtp_submit_set;
	struct ostream *output;
	const char *error = NULL;
	int ret;

	smtp_submit_set = *submit_set;
	smtp_submit_set.submission_host =
		t_strdup_printf("127.0.0.1:%u", bind_ports[0]);
	smtp_submit_set.submission_timeout = 1000;

	test_smtp_submit_input_init(&smtp_input);
	smtp_submit = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(smtp_submit, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	smtp_submit_add_rcpt(smtp_submit, &((struct smtp_address){
			.localpart = "rcpt2",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit);
	o_stream_nsend_str(output, test_message1);

	ret = smtp_submit_run(smtp_submit, &error);
	test_out_reason("run (ret == 0)", ret == 0, error);

	smtp_submit_deinit(&smtp_submit);

	return FALSE;
}

/* test */

static void test_denied_second_rcpt(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);

	test_begin("denied second rcpt");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_denied_second_rcpt,
			       test_server_denied_second_rcpt, 1);
	test_end();
}

/*
 * Denied DATA
 */

/* server */

enum _denied_data_state {
	DENIED_DATA_STATE_EHLO = 0,
	DENIED_DATA_STATE_MAIL_FROM,
	DENIED_DATA_STATE_RCPT_TO,
	DENIED_DATA_STATE_DATA
};

struct _denied_data_server {
	enum _denied_data_state state;
};

static void test_denied_data_input(struct server_connection *conn)
{
	struct _denied_data_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _denied_data_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _denied_data_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DENIED_DATA_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DENIED_DATA_STATE_MAIL_FROM;
			return;
		case DENIED_DATA_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = DENIED_DATA_STATE_RCPT_TO;
			continue;
		case DENIED_DATA_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.5 Ok\r\n");
			ctx->state = DENIED_DATA_STATE_DATA;
			continue;
		case DENIED_DATA_STATE_DATA:
			o_stream_nsend_str(conn->conn.output, "500 5.0.0 "
					   "Unacceptable recipients\r\n");
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_denied_data_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_denied_data(unsigned int index)
{
	test_server_init = test_denied_data_init;
	test_server_input = test_denied_data_input;
	test_server_run(index);
}

/* client */

static bool
test_client_denied_data(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret == 0)", ret == 0, error);

	return FALSE;
}

/* test */

static void test_denied_data(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("denied data");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_denied_data,
			       test_server_denied_data, 1);
	test_end();
}

/*
 * Data failure
 */

/* server */

enum _data_failure_state {
	DATA_FAILURE_STATE_EHLO = 0,
	DATA_FAILURE_STATE_MAIL_FROM,
	DATA_FAILURE_STATE_RCPT_TO,
	DATA_FAILURE_STATE_DATA,
	DATA_FAILURE_STATE_FINISH
};

struct _data_failure_server {
	enum _data_failure_state state;
};

static void test_data_failure_input(struct server_connection *conn)
{
	struct _data_failure_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _data_failure_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _data_failure_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DATA_FAILURE_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DATA_FAILURE_STATE_MAIL_FROM;
			return;
		case DATA_FAILURE_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = DATA_FAILURE_STATE_RCPT_TO;
			continue;
		case DATA_FAILURE_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.5 Ok\r\n");
			ctx->state = DATA_FAILURE_STATE_DATA;
			continue;
		case DATA_FAILURE_STATE_DATA:
			o_stream_nsend_str(
				conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			ctx->state = DATA_FAILURE_STATE_FINISH;
			continue;
		case DATA_FAILURE_STATE_FINISH:
			if (strcmp(line, ".") == 0) {
				o_stream_nsend_str(
					conn->conn.output, "552 5.2.3 "
					"Message length exceeds administrative limit\r\n");
				server_connection_deinit(&conn);
				return;
			}
			continue;
		}
		i_unreached();
	}
}

static void test_data_failure_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_data_failure(unsigned int index)
{
	test_server_init = test_data_failure_init;
	test_server_input = test_data_failure_input;
	test_server_run(index);
}

/* client */

static bool
test_client_data_failure(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret == 0)", ret == 0, error);

	return FALSE;
}

/* test */

static void test_data_failure(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("data failure");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_data_failure,
			       test_server_data_failure, 1);
	test_end();
}

/*
 * Data disconnect
 */

/* server */

enum _data_disconnect_state {
	DATA_DISCONNECT_STATE_EHLO = 0,
	DATA_DISCONNECT_STATE_MAIL_FROM,
	DATA_DISCONNECT_STATE_RCPT_TO,
	DATA_DISCONNECT_STATE_DATA,
	DATA_DISCONNECT_STATE_FINISH
};

struct _data_disconnect_server {
	enum _data_disconnect_state state;
};

static void test_data_disconnect_input(struct server_connection *conn)
{
	struct _data_disconnect_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _data_disconnect_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _data_disconnect_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DATA_DISCONNECT_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DATA_DISCONNECT_STATE_MAIL_FROM;
			return;
		case DATA_DISCONNECT_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = DATA_DISCONNECT_STATE_RCPT_TO;
			continue;
		case DATA_DISCONNECT_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.5 Ok\r\n");
			ctx->state = DATA_DISCONNECT_STATE_DATA;
			continue;
		case DATA_DISCONNECT_STATE_DATA:
			o_stream_nsend_str(
				conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			ctx->state = DATA_DISCONNECT_STATE_FINISH;
			continue;
		case DATA_DISCONNECT_STATE_FINISH:
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_data_disconnect_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_data_disconnect(unsigned int index)
{
	test_server_init = test_data_disconnect_init;
	test_server_input = test_data_disconnect_input;
	test_server_run(index);
}

/* client */

static bool
test_client_data_disconnect(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	return FALSE;
}

/* test */

static void test_data_disconnect(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 5;

	test_begin("data disconnect");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_data_disconnect,
			       test_server_data_disconnect, 1);
	test_end();
}

/*
 * Data timout
 */

/* server */

enum _data_timout_state {
	DATA_TIMEOUT_STATE_EHLO = 0,
	DATA_TIMEOUT_STATE_MAIL_FROM,
	DATA_TIMEOUT_STATE_RCPT_TO,
	DATA_TIMEOUT_STATE_DATA,
	DATA_TIMEOUT_STATE_FINISH
};

struct _data_timout_server {
	enum _data_timout_state state;
};

static void test_data_timout_input(struct server_connection *conn)
{
	struct _data_timout_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _data_timout_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _data_timout_server *)conn->context;
	}

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case DATA_TIMEOUT_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = DATA_TIMEOUT_STATE_MAIL_FROM;
			return;
		case DATA_TIMEOUT_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = DATA_TIMEOUT_STATE_RCPT_TO;
			continue;
		case DATA_TIMEOUT_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.5 Ok\r\n");
			ctx->state = DATA_TIMEOUT_STATE_DATA;
			continue;
		case DATA_TIMEOUT_STATE_DATA:
			o_stream_nsend_str(
				conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			ctx->state = DATA_TIMEOUT_STATE_FINISH;
			continue;
		case DATA_TIMEOUT_STATE_FINISH:
			i_sleep_intr_secs(10);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_data_timout_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_server_data_timout(unsigned int index)
{
	test_server_init = test_data_timout_init;
	test_server_input = test_data_timout_input;
	test_server_run(index);
}

/* client */

static bool
test_client_data_timout(const struct smtp_submit_settings *submit_set)
{
	time_t time;
	const char *error = NULL;
	int ret;

	io_loop_time_refresh();
	time = ioloop_time;
	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	io_loop_time_refresh();
	test_out("timeout", (ioloop_time - time) < 5);

	return FALSE;
}

/* test */

static void test_data_timeout(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);
	smtp_submit_set.submission_timeout = 2;

	test_begin("data timeout");
	test_expect_errors(1);
	test_run_client_server(&smtp_submit_set,
			       test_client_data_timout,
			       test_server_data_timout, 1);
	test_end();
}

/*
 * Successful delivery
 */

/* server */

enum _successful_delivery_state {
	SUCCESSFUL_DELIVERY_STATE_EHLO = 0,
	SUCCESSFUL_DELIVERY_STATE_MAIL_FROM,
	SUCCESSFUL_DELIVERY_STATE_RCPT_TO,
	SUCCESSFUL_DELIVERY_STATE_DATA,
	SUCCESSFUL_DELIVERY_STATE_FINISH
};

struct _successful_delivery_server {
	enum _successful_delivery_state state;

	char *file_path;
	struct istream *dot_input;
	struct ostream *file;
};

static void test_successful_delivery_input(struct server_connection *conn)
{
	struct _successful_delivery_server *ctx;
	const char *line;

	if (conn->context == NULL) {
		ctx = p_new(conn->pool, struct _successful_delivery_server, 1);
		conn->context = (void*)ctx;
	} else {
		ctx = (struct _successful_delivery_server *)conn->context;
	}

	// FIXME: take structure from test-smtp-client-errors

	for (;;) {
		if (ctx->state == SUCCESSFUL_DELIVERY_STATE_FINISH) {
			enum ostream_send_istream_result res;

			if (ctx->dot_input == NULL) {
				int fd;

				ctx->dot_input =
					i_stream_create_dot(conn->conn.input, TRUE);
				ctx->file_path = p_strdup_printf(
					conn->pool, "%s/message-%u.eml",
					test_tmp_dir_get(), server_port);

				if ((fd = open(ctx->file_path, O_WRONLY | O_CREAT,
					       0600)) < 0) {
					i_fatal("failed create tmp file for message: "
						"open(%s) failed: %m",
						ctx->file_path);
				}
				ctx->file = o_stream_create_fd_autoclose(
					&fd, IO_BLOCK_SIZE);
			}

			res = o_stream_send_istream(ctx->file, ctx->dot_input);
			switch (res) {
			case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
				break;
			case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
			case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
				return;
			case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
				i_error("test server: "
					"Failed to read all message payload [%s]",
					ctx->file_path);
				server_connection_deinit(&conn);
				return;
			case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
				i_error("test server: "
					"Failed to write all message payload [%s]",
					ctx->file_path);
				server_connection_deinit(&conn);
				return;
			}

			o_stream_nsend_str(
				conn->conn.output,
				"250 2.0.0 Ok: queued as 73BDE342129\r\n");
			ctx->state = SUCCESSFUL_DELIVERY_STATE_MAIL_FROM;
			continue;
		}

		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case SUCCESSFUL_DELIVERY_STATE_EHLO:
			o_stream_nsend_str(conn->conn.output,
					   "250-testserver\r\n"
					   "250-PIPELINING\r\n"
					   "250-ENHANCEDSTATUSCODES\r\n"
					   "250-8BITMIME\r\n"
					   "250 DSN\r\n");
			ctx->state = SUCCESSFUL_DELIVERY_STATE_MAIL_FROM;
			return;
		case SUCCESSFUL_DELIVERY_STATE_MAIL_FROM:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.0 Ok\r\n");
			ctx->state = SUCCESSFUL_DELIVERY_STATE_RCPT_TO;
			continue;
		case SUCCESSFUL_DELIVERY_STATE_RCPT_TO:
			o_stream_nsend_str(conn->conn.output,
					   "250 2.1.5 Ok\r\n");
			ctx->state = SUCCESSFUL_DELIVERY_STATE_DATA;
			continue;
		case SUCCESSFUL_DELIVERY_STATE_DATA:
			o_stream_nsend_str(
				conn->conn.output,
				"354 End data with <CR><LF>.<CR><LF>\r\n");
			ctx->state = SUCCESSFUL_DELIVERY_STATE_FINISH;
			continue;
		case SUCCESSFUL_DELIVERY_STATE_FINISH:
			break;
		}
		i_unreached();
	}
}

static void test_successful_delivery_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"220 testserver ESMTP Testfix (Debian/GNU)\r\n");
}

static void test_successful_delivery_deinit(struct server_connection *conn)
{
	struct _successful_delivery_server *ctx =
		(struct _successful_delivery_server *)conn->context;

	i_stream_unref(&ctx->dot_input);
	o_stream_unref(&ctx->file);
}

static void test_server_successful_delivery(unsigned int index)
{
	test_server_init = test_successful_delivery_init;
	test_server_input = test_successful_delivery_input;
	test_server_deinit = test_successful_delivery_deinit;
	test_server_run(index);
}

/* client */

static bool
test_client_successful_delivery(const struct smtp_submit_settings *submit_set)
{
	const char *error = NULL;
	int ret;

	/* send the message */
	ret = test_client_smtp_send_simple_port(submit_set, test_message1,
						bind_ports[0], &error);
	test_out_reason("run (ret > 0)", ret > 0, error);

	/* verify delivery */
	test_message_delivery(test_message1,
			      t_strdup_printf("%s/message-%u.eml",
					      test_tmp_dir_get(),
					      bind_ports[0]));

	return FALSE;
}

struct _parallel_delivery_client {
	unsigned int count;
};

static void
test_client_parallel_delivery_callback(const struct smtp_submit_result *result,
				       struct _parallel_delivery_client *ctx)
{
	if (result->status <= 0)
		i_error("Submit failed: %s", result->error);

	if (--ctx->count == 0)
		io_loop_stop(current_ioloop);
}

static bool
test_client_parallel_delivery(const struct smtp_submit_settings *submit_set)
{
	struct smtp_submit_input smtp_input;
	struct smtp_submit_settings smtp_submit_set;
	struct _parallel_delivery_client *ctx;
	struct smtp_submit *smtp_submit1, *smtp_submit2;
	struct ostream *output;
	struct ioloop *ioloop;

	ioloop = io_loop_create();

	ctx = i_new(struct _parallel_delivery_client, 1);
	ctx->count = 2;

	smtp_submit_set = *submit_set;
	smtp_submit_set.submission_timeout = 5;

	/* submit 1 */
	test_smtp_submit_input_init(&smtp_input);
	smtp_submit_set.submission_host =
		t_strdup_printf("127.0.0.1:%u",  bind_ports[0]);
	smtp_submit1 = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(
		smtp_submit1, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit1);
	o_stream_nsend_str(output, test_message1);

	smtp_submit_run_async(
		smtp_submit1, test_client_parallel_delivery_callback, ctx);

	/* submit 2 */
	test_smtp_submit_input_init(&smtp_input);
	smtp_submit_set.submission_host =
		t_strdup_printf("127.0.0.1:%u",  bind_ports[1]);
	smtp_submit2 = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(
		smtp_submit2, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit2);
	o_stream_nsend_str(output, test_message2);

	smtp_submit_run_async(
		smtp_submit2, test_client_parallel_delivery_callback, ctx);

	io_loop_run(ioloop);

	smtp_submit_deinit(&smtp_submit1);
	smtp_submit_deinit(&smtp_submit2);
	io_loop_destroy(&ioloop);

	/* verify delivery */
	test_message_delivery(test_message1,
			      t_strdup_printf("%s/message-%u.eml",
					      test_tmp_dir_get(),
					      bind_ports[0]));
	test_message_delivery(test_message2,
			      t_strdup_printf("%s/message-%u.eml",
					      test_tmp_dir_get(),
					      bind_ports[1]));
	i_free(ctx);

	return FALSE;
}

/* test */

static void test_successful_delivery(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);

	test_begin("successful delivery");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_successful_delivery,
			       test_server_successful_delivery, 1);
	test_end();

	test_begin("parallel delivery");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_parallel_delivery,
			       test_server_successful_delivery, 2);
	test_end();
}

/*
 * Failed sendmail
 */

/* client */

static bool
test_client_failed_sendmail(const struct smtp_submit_settings *submit_set)
{
	struct smtp_submit_settings smtp_submit_set;
	struct smtp_submit_input smtp_input;
	struct smtp_submit *smtp_submit;
	struct ostream *output;
	const char *sendmail_path, *error = NULL;
	int ret;

	sendmail_path = TEST_BIN_DIR"/sendmail-exit-1.sh";

	smtp_submit_set = *submit_set;
	smtp_submit_set.sendmail_path = sendmail_path;
	smtp_submit_set.submission_timeout = 5;

	test_smtp_submit_input_init(&smtp_input);
	smtp_submit = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(smtp_submit, &((struct smtp_address){
		.localpart = "rcpt",
		.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit);
	o_stream_nsend_str(output, test_message1);

	ret = smtp_submit_run(smtp_submit, &error);
	test_out_reason("run (ret < 0)", ret < 0, error);

	smtp_submit_deinit(&smtp_submit);

	return FALSE;
}

/* test */

static void test_failed_sendmail(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);

	test_begin("failed sendmail");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_failed_sendmail, NULL, 0);
	test_end();
}

/*
 * Successful sendmail
 */

/* client */

static bool
test_client_successful_sendmail(const struct smtp_submit_settings *submit_set)
{
	struct smtp_submit_input smtp_input;
	struct smtp_submit_settings smtp_submit_set;
	struct smtp_submit *smtp_submit;
	struct ostream *output;
	const char *sendmail_path, *msg_path, *error = NULL;
	int ret;

	msg_path = t_strdup_printf("%s/message.eml", test_tmp_dir_get());

	sendmail_path = t_strdup_printf(
		TEST_BIN_DIR"/sendmail-success.sh %s", msg_path);

	smtp_submit_set = *submit_set;
	smtp_submit_set.sendmail_path = sendmail_path;
	smtp_submit_set.submission_timeout = 5;

	test_smtp_submit_input_init(&smtp_input);
	smtp_submit = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(smtp_submit, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit);
	o_stream_nsend_str(output, test_message1);

	ret = smtp_submit_run(smtp_submit, &error);
	test_out_reason("run (ret > 0)", ret > 0, error);

	smtp_submit_deinit(&smtp_submit);

	/* verify delivery */
	test_message_delivery(test_message1, msg_path);

	return FALSE;
}

/* test */

static void test_successful_sendmail(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);

	test_begin("successful sendmail");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_successful_sendmail, NULL, 0);
	test_end();
}

/*
 * Parallel sendmail
 */

/* client */

struct _parallel_sendmail_client {
	unsigned int count;
};

static void
test_client_parallel_sendmail_callback(const struct smtp_submit_result *result,
				       struct _parallel_sendmail_client *ctx)
{
	if (result->status <= 0)
		i_error("Submit failed: %s", result->error);

	if (--ctx->count == 0)
		io_loop_stop(current_ioloop);
}

static bool
test_client_parallel_sendmail(const struct smtp_submit_settings *submit_set)
{
	struct smtp_submit_input smtp_input;
	struct smtp_submit_settings smtp_submit_set;
	struct _parallel_sendmail_client *ctx;
	struct smtp_submit *smtp_submit1, *smtp_submit2;
	struct ostream *output;
	const char *sendmail_path1, *sendmail_path2;
	const char *msg_path1, *msg_path2;
	struct ioloop *ioloop;

	ctx = i_new(struct _parallel_sendmail_client, 1);
	ctx->count = 2;

	ioloop = io_loop_create();

	msg_path1 = t_strdup_printf("%s/message1.eml", test_tmp_dir_get());
	msg_path2 = t_strdup_printf("%s/message2.eml", test_tmp_dir_get());

	sendmail_path1 = t_strdup_printf(
		TEST_BIN_DIR"/sendmail-success.sh %s", msg_path1);
	sendmail_path2 = t_strdup_printf(
		TEST_BIN_DIR"/sendmail-success.sh %s", msg_path2);

	smtp_submit_set = *submit_set;
	smtp_submit_set.submission_timeout = 5;

	/* submit 1 */
	test_smtp_submit_input_init(&smtp_input);
	smtp_submit_set.sendmail_path = sendmail_path1;
	smtp_submit1 = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(
		smtp_submit1, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit1);
	o_stream_nsend_str(output, test_message1);

	smtp_submit_run_async(
		smtp_submit1, test_client_parallel_sendmail_callback, ctx);

	/* submit 2 */
	test_smtp_submit_input_init(&smtp_input);
	smtp_submit_set.sendmail_path = sendmail_path2;
	smtp_submit2 = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(
		smtp_submit2, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit2);
	o_stream_nsend_str(output, test_message2);

	smtp_submit_run_async(
		smtp_submit2, test_client_parallel_sendmail_callback, ctx);

	io_loop_run(ioloop);

	smtp_submit_deinit(&smtp_submit1);
	smtp_submit_deinit(&smtp_submit2);
	io_loop_destroy(&ioloop);

	/* verify delivery */
	test_message_delivery(test_message1, msg_path1);
	test_message_delivery(test_message2, msg_path2);

	i_free(ctx);

	return FALSE;
}

/* test */

static void test_parallel_sendmail(void)
{
	struct smtp_submit_settings smtp_submit_set;

	test_client_defaults(&smtp_submit_set);

	test_begin("parallel sendmail");
	test_expect_errors(0);
	test_run_client_server(&smtp_submit_set,
			       test_client_parallel_sendmail, NULL, 0);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_host_lookup_failed,
	test_connection_refused,
	test_connection_timed_out,
	test_bad_greeting,
	test_denied_helo,
	test_disconnect_helo,
	test_denied_mail,
	test_denied_rcpt,
	test_denied_second_rcpt,
	test_denied_data,
	test_data_failure,
	test_data_disconnect,
	test_data_timeout,
	test_successful_delivery,
	test_failed_sendmail,
	test_successful_sendmail,
	test_parallel_sendmail,
	NULL
};

/*
 * Test client
 */

static void test_client_defaults(struct smtp_submit_settings *smtp_set)
{
	i_zero(smtp_set);
	smtp_set->hostname = "test";
	smtp_set->submission_host = "";
	smtp_set->sendmail_path = "/bin/false";
	smtp_set->mail_debug = debug;
}

static void test_client_deinit(void)
{
}

static int
test_client_smtp_send_simple(const struct smtp_submit_settings *smtp_set,
			     const char *message, const char *host,
			     const char **error_r)
{
	struct smtp_submit_input smtp_input;
	struct smtp_submit_settings smtp_submit_set;
	struct smtp_submit *smtp_submit;
	struct ostream *output;
	int ret;

	/* send the message */
	smtp_submit_set = *smtp_set;
	smtp_submit_set.submission_host = host,

	i_zero(&smtp_input);
	smtp_submit = smtp_submit_init_simple(
		&smtp_input, &smtp_submit_set, &((struct smtp_address){
			.localpart = "sender",
			.domain = "example.com"}));

	smtp_submit_add_rcpt(
		smtp_submit, &((struct smtp_address){
			.localpart = "rcpt",
			.domain = "example.com"}));
	output = smtp_submit_send(smtp_submit);
	o_stream_nsend_str(output, message);

	ret = smtp_submit_run(smtp_submit, error_r);

	smtp_submit_deinit(&smtp_submit);

	return ret;
}

static int
test_client_smtp_send_simple_port(const struct smtp_submit_settings *smtp_set,
				  const char *message, unsigned int port,
				  const char **error_r)
{
	const char *host = t_strdup_printf("127.0.0.1:%u", port);

	return test_client_smtp_send_simple(smtp_set, message, host, error_r);
}

/*
 * Test server
 */

/* client connection */

static void server_connection_input(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;

	test_server_input(conn);
}

static void server_connection_init(int fd)
{
	struct server_connection *conn;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("server connection", 256);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;

	connection_init_server(server_conn_list, &conn->conn,
			       "server connection", fd, fd);

	if (test_server_init != NULL)
		test_server_init(conn);
}

static void server_connection_deinit(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;

	*_conn = NULL;

	if (test_server_deinit != NULL)
		test_server_deinit(conn);

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void server_connection_destroy(struct connection *_conn)
{
	struct server_connection *conn =
		(struct server_connection *)_conn;

	server_connection_deinit(&conn);
}

static void server_connection_accept(void *context ATTR_UNUSED)
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

	server_conn_list = connection_list_init(&server_connection_set,
						&server_connection_vfuncs);

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
}

static void test_tmp_dir_init(void)
{
	tmp_dir = i_strdup_printf("/tmp/dovecot-test-smtp-client.%s.%s",
				  dec2str(time(NULL)), dec2str(getpid()));
}

static const char *test_tmp_dir_get(void)
{
	if (mkdir(tmp_dir, 0700) < 0 && errno != EEXIST) {
		i_fatal("failed to create temporary directory `%s': %m",
			tmp_dir);
	}
	return tmp_dir;
}

static void test_tmp_dir_deinit(void)
{
	const char *error;

	if (unlink_directory(tmp_dir, UNLINK_DIRECTORY_FLAG_RMDIR,
			     &error) < 0) {
		i_warning("failed to remove temporary directory `%s': %s.",
			  tmp_dir, error);
	}

	i_free(tmp_dir);
}

static void test_message_delivery(const char *message, const char *file)
{
	struct istream *input;
	const unsigned char *data;
	size_t size, msize;
	int ret;

	msize = strlen(message);

	input = i_stream_create_file(file, (size_t)-1);
	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		const unsigned char *mdata;

		test_assert(input->v_offset < (uoff_t)msize &&
			    (input->v_offset + (uoff_t)size) <= (uoff_t)msize);
		if (test_has_failed())
			break;
		mdata = (const unsigned char *)message + input->v_offset;
		test_assert(memcmp(data, mdata, size) == 0);
		if (test_has_failed())
			break;
		i_stream_skip(input, size);
	}

	test_out_reason("delivery", ret < 0 &&
			input->stream_errno == 0 &&
			input->eof &&
			input->v_offset == (uoff_t)msize,
			(input->stream_errno == 0 ?
			 NULL : i_stream_get_error(input)));
	i_stream_unref(&input);
}

static void
test_run_client_server(const struct smtp_submit_settings *submit_set,
		       test_client_init_t client_test,
		       test_server_init_t server_test,
		       unsigned int server_tests_count)
{
	unsigned int i;

	server_pids = NULL;
	server_pids_count = 0;

	test_tmp_dir_init();

	if (server_tests_count > 0) {
		int fds[server_tests_count];

		bind_ports = i_new(in_port_t, server_tests_count);

		lib_signals_ioloop_detach();

		server_pids = i_new(pid_t, server_tests_count);
		for (i = 0; i < server_tests_count; i++)
			server_pids[i] = (pid_t)-1;
		server_pids_count = server_tests_count;

		for (i = 0; i < server_tests_count; i++)
			fds[i] = test_open_server_fd(&bind_ports[i]);

		for (i = 0; i < server_tests_count; i++) {
			fd_listen = fds[i];
			server_port = bind_ports[i];
			if ((server_pids[i] = fork()) == (pid_t)-1)
				i_fatal("fork() failed: %m");
			if (server_pids[i] == 0) {
				server_pids[i] = (pid_t)-1;
				server_pids_count = 0;
				hostpid_init();
				while (current_ioloop != NULL) {
					ioloop = current_ioloop;
					io_loop_destroy(&ioloop);
				}
				lib_signals_deinit();
				/* child: server */
				i_set_failure_prefix("SERVER[%u]: ", i + 1);
				if (debug)
					i_debug("PID=%s", my_pid);
				ioloop = io_loop_create();
				server_test(i);
				io_loop_destroy(&ioloop);
				if (fd_listen != -1)
					i_close_fd(&fd_listen);
				i_free(bind_ports);
				i_free(server_pids);
				test_tmp_dir_deinit();
				/* wait for it to be killed; this way, valgrind
				   will not object to this process going away
				   inelegantly. */
				i_sleep_intr_secs(60);
				exit(1);
			}
			if (fd_listen != -1)
				i_close_fd(&fd_listen);
		}
		lib_signals_ioloop_attach();
	}

	/* parent: client */
	i_set_failure_prefix("CLIENT: ");
	if (debug)
		i_debug("PID=%s", my_pid);

	i_sleep_msecs(100); /* wait a little for server setup */
	server_port = 0;

	ioloop = io_loop_create();
	if (client_test(submit_set))
		io_loop_run(ioloop);
	test_client_deinit();
	io_loop_destroy(&ioloop);

	i_unset_failure_prefix();
	test_servers_kill_all();
	i_free(server_pids);
	i_free(bind_ports);
	test_tmp_dir_deinit();
}

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void test_signal_handler(const siginfo_t *si, void *context ATTR_UNUSED)
{
	int signo = si->si_signo;

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
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int c;
	int ret;

	master_service = master_service_init("test-smtp-submit", service_flags,
					     &argc, &argv, "D");

	atexit(test_atexit);
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_set_handler(SIGTERM, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGQUIT, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGINT, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGSEGV, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGABRT, 0, test_signal_handler, NULL);

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	master_service_init_finish(master_service);

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	ret = test_run(test_functions);

	master_service_deinit(&master_service);

	return ret;
}
