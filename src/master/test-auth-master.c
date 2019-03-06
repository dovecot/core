/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "strescape.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-chain.h"
#include "ostream.h"
#include "time-util.h"
#include "unlink-directory.h"
#include "write-full.h"
#include "connection.h"
#include "master-service.h"
#include "master-interface.h"
#include "test-common.h"

#include "auth-master.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#define TEST_SOCKET "./auth-master-test"

/*
 * Types
 */

struct server_connection {
	struct connection conn;

	void *context;

	pool_t pool;
};

typedef void test_server_init_t(void);
typedef bool test_client_init_t(void);

/*
 * State
 */

/* common */
static struct ioloop *ioloop;
static bool debug = FALSE;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static pid_t server_pid;
static struct connection_list *server_conn_list;
static void (*test_server_input)(struct server_connection *conn);
static void (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);

/* client */

/*
 * Forward declarations
 */

/* server */
static void test_server_run(void);
static void server_connection_deinit(struct server_connection **_conn);

/* client */
static void test_client_deinit(void);

static int
test_client_passdb_lookup_simple(const char *user, bool retry,
				 const char **error_r);
static int
test_client_userdb_lookup_simple(const char *user, const char **error_r);
static int test_client_user_list_simple(void);

/* test*/
static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test) ATTR_NULL(2);

/*
 * Connection refused
 */

/* server */

static void
test_server_connection_refused(void)
{
	i_close_fd(&fd_listen);
}

/* client */

static bool
test_client_connection_refused(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("harrie", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);

	return FALSE;
}

/* test */

static void test_connection_refused(void)
{
	test_begin("connection refused");
	test_expect_error_string("Connection refused");
	test_run_client_server(test_client_connection_refused,
			       test_server_connection_refused);
	test_end();
}

/*
 * Connection timed out
 */

/* server */

static void
test_connection_timed_out_input(struct server_connection *conn)
{
	sleep(5);
	server_connection_deinit(&conn);
}

static void test_server_connection_timed_out(void)
{
	test_server_input = test_connection_timed_out_input;
	test_server_run();
}

/* client */

static bool
test_client_connection_timed_out(void)
{
	time_t time;
	const char *error;
	int ret;

	io_loop_time_refresh();
	time = ioloop_time;

	ret = test_client_passdb_lookup_simple("harrie", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);

	io_loop_time_refresh();
	test_out("timeout", (ioloop_time - time) < 5);
	return FALSE;
}

/* test */

static void test_connection_timed_out(void)
{
	test_begin("connection timed out");
	test_expect_error_string("Connecting timed out");
	test_run_client_server(test_client_connection_timed_out,
			       test_server_connection_timed_out);
	test_end();
}

/*
 * Bad VERSION
 */

/* server */

static void
test_bad_version_input(struct server_connection *conn)
{
	server_connection_deinit(&conn);
}

static void
test_bad_version_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"VERSION\t666\t666\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_bad_version(void)
{
	test_server_init = test_bad_version_init;
	test_server_input = test_bad_version_input;
	test_server_run();
}

/* client */

static bool
test_client_bad_version(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("harrie", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);
	return FALSE;
}

/* test */

static void test_bad_version(void)
{
	test_begin("bad version");
	test_expect_error_string("Socket supports major version 666");
	test_run_client_server(test_client_bad_version,
			       test_server_bad_version);
	test_end();
}

/*
 * Disconnect VERSION
 */

/* server */

static void
test_disconnect_version_input(struct server_connection *conn)
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

static void
test_disconnect_version_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_disconnect_version(void)
{
	test_server_init = test_disconnect_version_init;
	test_server_input = test_disconnect_version_input;
	test_server_run();
}

/* client */

static bool
test_client_disconnect_version(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("harrie", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);
	return FALSE;
}

/* test */

static void test_disconnect_version(void)
{
	test_begin("disconnect version");
	test_expect_error_string("Disconnected unexpectedly");
	test_run_client_server(test_client_disconnect_version,
			       test_server_disconnect_version);
	test_end();
}

/*
 * Passdb FAIL
 */

/* server */

enum _passdb_fail_state {
	PASSDB_FAIL_STATE_VERSION = 0,
	PASSDB_FAIL_STATE_PASS
};

struct _passdb_fail_server {
	enum _passdb_fail_state state;

	bool not_found:1;
};

static void
test_passdb_fail_input(struct server_connection *conn)
{
	struct _passdb_fail_server *ctx =
		(struct _passdb_fail_server *)conn->context;
	const char *const *args;
	unsigned int id;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case PASSDB_FAIL_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = PASSDB_FAIL_STATE_PASS;
			continue;
		case PASSDB_FAIL_STATE_PASS:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "PASS") != 0 || args[1] == NULL ||
			    str_to_uint(args[1], &id) < 0 || args[2] == NULL) {
				i_error("Bad PASS request");
				server_connection_deinit(&conn);
				return;
			}
			if (strcmp(args[2], "henk") == 0) {
				line = t_strdup_printf("NOTFOUND\t%u\n", id);
			} else if (strcmp(args[2], "holger") == 0) {
				sleep(5);
				server_connection_deinit(&conn);
				return;
			} else {
				line = t_strdup_printf("FAIL\t%u\t"
					"reason=You shall not pass!!\n", id);
			}
			o_stream_nsend_str(conn->conn.output, line);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void
test_passdb_fail_init(struct server_connection *conn)
{
	struct _passdb_fail_server *ctx;

	ctx = p_new(conn->pool, struct _passdb_fail_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_passdb_fail(void)
{
	test_server_init = test_passdb_fail_init;
	test_server_input = test_passdb_fail_input;
	test_server_run();
}

/* client */

static bool
test_client_passdb_fail(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("harrie", FALSE, &error);
	test_out("run (ret == -2)", ret == -2);
	test_assert(error != NULL &&
		    strcmp(error, "You shall not pass!!") == 0);

	return FALSE;
}

static bool
test_client_passdb_notfound(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("henk", FALSE, &error);
	test_out("run (ret == 0)", ret == 0);
	test_assert(error == NULL);

	return FALSE;
}

static bool
test_client_passdb_timeout(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("holger", FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error == NULL);

	return FALSE;
}

/* test */

static void test_passdb_fail(void)
{
	test_begin("passdb fail");
	test_run_client_server(test_client_passdb_fail,
			       test_server_passdb_fail);
	test_end();

	test_begin("passdb notfound");
	test_run_client_server(test_client_passdb_notfound,
			       test_server_passdb_fail);
	test_end();

	test_begin("passdb timeout");
	test_expect_error_string("Request timed out");
	test_run_client_server(test_client_passdb_timeout,
			       test_server_passdb_fail);
	test_end();
}

/*
 * Userdb FAIL
 */

/* server */

enum _userdb_fail_state {
	USERDB_FAIL_STATE_VERSION = 0,
	USERDB_FAIL_STATE_USER
};

struct _userdb_fail_server {
	enum _userdb_fail_state state;

	bool not_found:1;
};

static void
test_userdb_fail_input(struct server_connection *conn)
{
	struct _userdb_fail_server *ctx =
		(struct _userdb_fail_server *)conn->context;
	const char *const *args;
	unsigned int id;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case USERDB_FAIL_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = USERDB_FAIL_STATE_USER;
			continue;
		case USERDB_FAIL_STATE_USER:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "USER") != 0 || args[1] == NULL ||
			    str_to_uint(args[1], &id) < 0) {
				i_error("Bad USER request");
				server_connection_deinit(&conn);
				return;
			}
			if (strcmp(args[2], "henk") == 0) {
				line = t_strdup_printf("NOTFOUND\t%u\n", id);
			} else if (strcmp(args[2], "holger") == 0) {
				sleep(5);
				server_connection_deinit(&conn);
				return;
			} else {
				line = t_strdup_printf("FAIL\t%u\t"
					"reason=It is no use!\n", id);
			}
			o_stream_nsend_str(conn->conn.output, line);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void
test_userdb_fail_init(struct server_connection *conn)
{
	struct _userdb_fail_server *ctx;

	ctx = p_new(conn->pool, struct _userdb_fail_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_userdb_fail(void)
{
	test_server_init = test_userdb_fail_init;
	test_server_input = test_userdb_fail_input;
	test_server_run();
}

/* client */

static bool
test_client_userdb_fail(void)
{
	const char *error;
	int ret;

	ret = test_client_userdb_lookup_simple("harrie", &error);
	test_out("run (ret == -2)", ret == -2);
	test_assert(error != NULL &&
		    strcmp(error, "It is no use!") == 0);

	return FALSE;
}

static bool
test_client_userdb_notfound(void)
{
	const char *error;
	int ret;

	ret = test_client_userdb_lookup_simple("henk", &error);
	test_out("run (ret == 0)", ret == 0);
	test_assert(error == NULL);

	return FALSE;
}

static bool
test_client_userdb_timeout(void)
{
	const char *error;
	int ret;

	ret = test_client_userdb_lookup_simple("holger", &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error == NULL);

	return FALSE;
}

/* test */

static void test_userdb_fail(void)
{
	test_begin("userdb fail");
	test_run_client_server(test_client_userdb_fail,
			       test_server_userdb_fail);
	test_end();

	test_begin("userdb notfound");
	test_run_client_server(test_client_userdb_notfound,
			       test_server_userdb_fail);
	test_end();

	test_begin("userdb timeout");
	test_expect_error_string("Request timed out");
	test_run_client_server(test_client_userdb_timeout,
			       test_server_userdb_fail);
	test_end();
}

/*
 * User list FAIL
 */

/* server */

enum _user_list_fail_state {
	USER_LIST_FAIL_STATE_VERSION = 0,
	USER_LIST_FAIL_STATE_USER
};

struct _user_list_fail_server {
	enum _user_list_fail_state state;
};

static void
test_user_list_fail_input(struct server_connection *conn)
{
	struct _user_list_fail_server *ctx =
		(struct _user_list_fail_server *)conn->context;
	const char *const *args;
	unsigned int id;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case USER_LIST_FAIL_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = USER_LIST_FAIL_STATE_USER;
			continue;
		case USER_LIST_FAIL_STATE_USER:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "LIST") != 0 || args[1] == NULL ||
			    str_to_uint(args[1], &id) < 0) {
				i_error("Bad LIST request");
				server_connection_deinit(&conn);
				return;
			}
			line = t_strdup_printf("DONE\t%u\tfail\n", id);
			o_stream_nsend_str(conn->conn.output, line);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void
test_user_list_fail_init(struct server_connection *conn)
{
	struct _user_list_fail_server *ctx;

	ctx = p_new(conn->pool, struct _user_list_fail_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_user_list_fail(void)
{
	test_server_init = test_user_list_fail_init;
	test_server_input = test_user_list_fail_input;
	test_server_run();
}

/* client */

static bool
test_client_user_list_fail(void)
{
	int ret;

	ret = test_client_user_list_simple();
	test_out("run (ret < 0)", ret < 0);

	return FALSE;
}

/* test */

static void test_user_list_fail(void)
{
	test_begin("user list fail");
	test_expect_errors(1);
	test_run_client_server(test_client_user_list_fail,
			       test_server_user_list_fail);
	test_end();
}

/*
 * Passdb lookup
 */

/* server */

enum _passdb_lookup_state {
	PASSDB_LOOKUP_STATE_VERSION = 0,
	PASSDB_LOOKUP_STATE_PASS
};

struct _passdb_lookup_server {
	enum _passdb_lookup_state state;
};

static void
test_passdb_lookup_input(struct server_connection *conn)
{
	struct _passdb_lookup_server *ctx =
		(struct _passdb_lookup_server *)conn->context;
	const char *const *args;
	unsigned int id;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case PASSDB_LOOKUP_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = PASSDB_LOOKUP_STATE_PASS;
			continue;
		case PASSDB_LOOKUP_STATE_PASS:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "PASS") != 0 || args[1] == NULL ||
			    str_to_uint(args[1], &id) < 0) {
				i_error("Bad PASS request");
				server_connection_deinit(&conn);
				return;
			}
			line = t_strdup_printf("PASS\t%u\tuser=frop\n", id);
			o_stream_nsend_str(conn->conn.output, line);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void
test_passdb_lookup_init(struct server_connection *conn)
{
	struct _passdb_lookup_server *ctx;

	ctx = p_new(conn->pool, struct _passdb_lookup_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_passdb_lookup(void)
{
	test_server_init = test_passdb_lookup_init;
	test_server_input = test_passdb_lookup_input;
	test_server_run();
}

/* client */

static bool
test_client_passdb_lookup(void)
{
	const char *error;
	int ret;

	ret = test_client_passdb_lookup_simple("harrie", FALSE, &error);
	test_out("run (ret > 0)", ret > 0);

	return FALSE;
}

/* test */

static void test_passdb_lookup(void)
{
	test_begin("passdb lookup");
	test_run_client_server(test_client_passdb_lookup,
			       test_server_passdb_lookup);
	test_end();
}

/*
 * Userdb lookup
 */

/* server */

enum _userdb_lookup_state {
	USERDB_LOOKUP_STATE_VERSION = 0,
	USERDB_LOOKUP_STATE_PASS
};

struct _userdb_lookup_server {
	enum _userdb_lookup_state state;
};

static void
test_userdb_lookup_input(struct server_connection *conn)
{
	struct _userdb_lookup_server *ctx =
		(struct _userdb_lookup_server *)conn->context;
	const char *const *args;
	unsigned int id;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case USERDB_LOOKUP_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = USERDB_LOOKUP_STATE_PASS;
			continue;
		case USERDB_LOOKUP_STATE_PASS:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "USER") != 0 || args[1] == NULL ||
			    str_to_uint(args[1], &id) < 0) {
				i_error("Bad PASS request");
				server_connection_deinit(&conn);
				return;
			}
			line = t_strdup_printf("USER\t%u\tharrie\t"
				"uid=1000\tgid=110\thome=/home/harrie\n", id);
			o_stream_nsend_str(conn->conn.output, line);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void
test_userdb_lookup_init(struct server_connection *conn)
{
	struct _userdb_lookup_server *ctx;

	ctx = p_new(conn->pool, struct _userdb_lookup_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_userdb_lookup(void)
{
	test_server_init = test_userdb_lookup_init;
	test_server_input = test_userdb_lookup_input;
	test_server_run();
}

/* client */

static bool
test_client_userdb_lookup(void)
{
	const char *error;
	int ret;

	ret = test_client_userdb_lookup_simple("harrie", &error);
	test_out("run (ret > 0)", ret > 0);

	return FALSE;
}

/* test */

static void test_userdb_lookup(void)
{
	test_begin("userdb lookup");
	test_run_client_server(test_client_userdb_lookup,
			       test_server_userdb_lookup);
	test_end();
}

/*
 * User list
 */

/* server */

enum _user_list_state {
	USER_LIST_STATE_VERSION = 0,
	USER_LIST_STATE_USER
};

struct _user_list_server {
	enum _user_list_state state;
};

static void
test_user_list_input(struct server_connection *conn)
{
	struct _user_list_server *ctx =
		(struct _user_list_server *)conn->context;
	const char *line;
	const char *const *args;
	unsigned int id;
	string_t *str;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case USER_LIST_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = USER_LIST_STATE_USER;
			continue;
		case USER_LIST_STATE_USER:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "LIST") != 0 || args[1] == NULL ||
			    str_to_uint(args[1], &id) < 0) {
				i_error("Bad LIST request");
				server_connection_deinit(&conn);
				return;
			}
			str = t_str_new(256);
			str_printfa(str, "LIST\t%u\tuser1\n", id);
			str_printfa(str, "LIST\t%u\tuser2\n", id);
			str_printfa(str, "LIST\t%u\tuser3\n", id);
			str_printfa(str, "LIST\t%u\tuser4\n", id);
			str_printfa(str, "DONE\t%u\n", id);
			o_stream_nsend_str(conn->conn.output, str_c(str));
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void
test_user_list_init(struct server_connection *conn)
{
	struct _user_list_server *ctx;

	ctx = p_new(conn->pool, struct _user_list_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output,
		"VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output,
		"SPID\t23234\n");
}

static void test_server_user_list(void)
{
	test_server_init = test_user_list_init;
	test_server_input = test_user_list_input;
	test_server_run();
}

/* client */

static bool
test_client_user_list(void)
{
	int ret;

	ret = test_client_user_list_simple();
	test_out("run (ret == 0)", ret == 0);

	return FALSE;
}

/* test */

static void test_user_list(void)
{
	test_begin("user list");
	test_expect_errors(0);
	test_run_client_server(test_client_user_list,
			       test_server_user_list);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_connection_refused,
	test_connection_timed_out,
	test_bad_version,
	test_disconnect_version,
	test_passdb_fail,
	test_userdb_fail,
	test_user_list_fail,
	test_passdb_lookup,
	test_userdb_lookup,
	test_user_list,
	NULL
};

/*
 * Test client
 */

static void test_client_deinit(void)
{
}

static int
test_client_passdb_lookup_simple(const char *username, bool retry,
				 const char **error_r)
{
	struct auth_master_connection *auth_conn;
	enum auth_master_flags flags = 0;
	struct auth_user_info info;
	const char *const *fields;
	pool_t pool;
	int ret;

	i_zero(&info);
	info.service = "test";
	info.debug = debug;

	if (debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;

	pool = pool_alloconly_create("test", 1024);

	auth_conn = auth_master_init(TEST_SOCKET, flags);
	auth_master_set_timeout(auth_conn, 1000);
	ret = auth_master_pass_lookup(auth_conn, username, &info,
				      pool, &fields);
	if (ret < 0 && retry) {
		ret = auth_master_pass_lookup(auth_conn, username, &info,
					      pool, &fields);
	}
	auth_master_deinit(&auth_conn);

	*error_r = (ret < 0 ? t_strdup(fields[0]) : NULL);
	pool_unref(&pool);

	return ret;
}

static int
test_client_userdb_lookup_simple(const char *username, const char **error_r)
{
	struct auth_master_connection *auth_conn;
	enum auth_master_flags flags = 0;
	struct auth_user_info info;
	const char *const *fields;
	pool_t pool;
	int ret;

	i_zero(&info);
	info.service = "test";
	info.debug = debug;

	if (debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;

	pool = pool_alloconly_create("test", 1024);

	auth_conn = auth_master_init(TEST_SOCKET, flags);
	auth_master_set_timeout(auth_conn, 1000);
	ret = auth_master_user_lookup(auth_conn, username, &info,
				      pool, &username, &fields);
	auth_master_deinit(&auth_conn);

	*error_r = (ret < 0 ? t_strdup(fields[0]) : NULL);
	pool_unref(&pool);

	return ret;
}

static int test_client_user_list_simple(void)
{
	struct auth_master_connection *auth_conn;
	struct auth_master_user_list_ctx *list_ctx;
	enum auth_master_flags flags = 0;
	struct auth_user_info info;
	const char *user;
	int ret;

	i_zero(&info);
	info.service = "test";
	info.debug = debug;

	if (debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;

	auth_conn = auth_master_init(TEST_SOCKET, flags);
	auth_master_set_timeout(auth_conn, 1000);
	list_ctx = auth_master_user_list_init(auth_conn, "*", &info);
	while ((user = auth_master_user_list_next(list_ctx)) != NULL);
	ret = auth_master_user_list_deinit(&list_ctx);
	auth_master_deinit(&auth_conn);

	return ret;
}

/*
 * Test server
 */

/* client connection */

static void
server_connection_input(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;

	test_server_input(conn);
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

	if (test_server_init != NULL)
		test_server_init(conn);
}

static void
server_connection_deinit(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;

	*_conn = NULL;

	if (test_server_deinit != NULL)
		test_server_deinit(conn);

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

static void test_server_run(void)
{
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

static int test_open_server_fd(void)
{
	int fd;
	i_unlink_if_exists(TEST_SOCKET);
	fd = net_listen_unix(TEST_SOCKET, 128);
	if (debug)
		i_debug("server listening on "TEST_SOCKET);
	if (fd == -1)
		i_fatal("listen("TEST_SOCKET") failed: %m");
	return fd;
}

static void test_server_kill(void)
{
	if (server_pid != (pid_t)-1) {
		(void)kill(server_pid, SIGKILL);
		(void)waitpid(server_pid, NULL, 0);
		server_pid = -1;
	}
}

static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test)
{
	if (server_test != NULL) {
		lib_signals_ioloop_detach();

		server_pid = (pid_t)-1;

		fd_listen = test_open_server_fd();

		if ((server_pid = fork()) == (pid_t)-1)
			i_fatal("fork() failed: %m");
		if (server_pid == 0) {
			server_pid = (pid_t)-1;
			hostpid_init();
			while (current_ioloop != NULL) {
				ioloop = current_ioloop;
				io_loop_destroy(&ioloop);
			}
			lib_signals_deinit();
			if (debug)
				i_debug("server: PID=%s", my_pid);
			/* child: server */
			ioloop = io_loop_create();
			server_test();
			io_loop_destroy(&ioloop);
			if (fd_listen != -1)
				i_close_fd(&fd_listen);
			/* wait for it to be killed; this way, valgrind will not
			   object to this process going away inelegantly. */
			sleep(60);
			exit(1);
		}
		if (fd_listen != -1)
			i_close_fd(&fd_listen);
		if (debug)
			i_debug("client: PID=%s", my_pid);

		lib_signals_ioloop_attach();
	}

	/* parent: client */

	usleep(100000); /* wait a little for server setup */

	ioloop = io_loop_create();
	if (client_test())
		io_loop_run(ioloop);
	test_client_deinit();
	io_loop_destroy(&ioloop);

	test_server_kill();
	i_unlink_if_exists(TEST_SOCKET);
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
	test_server_kill();
	(void)unlink(TEST_SOCKET);

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_server_kill();
	(void)unlink(TEST_SOCKET);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;
	int c;
	int ret;

	atexit(test_atexit);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);

	master_service = master_service_init("test-auth-master", service_flags,
					     &argc, &argv, "D");

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

	ret = test_run(test_functions);

	master_service_deinit(&master_service);

	return ret;
}
