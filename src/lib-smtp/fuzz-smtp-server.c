/* Copyright (c) 2020 Catena cyber */

#include "lib.h"
#include "fuzzer.h"
#include "ioloop.h"
#include "smtp-server.h"

static void server_connection_destroy(void *context)
{
	struct ioloop *ioloop = context;
	io_loop_stop(ioloop);
}

static void test_server_continue(void *unused)
{
	//instead of simple io_loop_stop so as to free input io
	io_loop_stop_delayed(current_ioloop);
}

FUZZ_BEGIN_DATA(const uint8_t *data, size_t size)
{
	struct smtp_server_connection *conn;
	struct smtp_server_settings smtp_server_set = {
		.max_client_idle_time_msecs = 500,
		.max_pipelined_commands = 16,
		.auth_optional = TRUE,
	};
	struct smtp_server_callbacks server_callbacks = {
		.conn_destroy = server_connection_destroy,
	};
	struct smtp_server *smtp_server = NULL;
	struct ioloop *ioloop;
	int fd;
	struct timeout *to;

	ioloop = io_loop_create();
	to = timeout_add_short(0, test_server_continue, NULL);
	smtp_server = smtp_server_init(&smtp_server_set);

	fd = fuzzer_io_as_fd(data, size);
	conn = smtp_server_connection_create(smtp_server, fd, fd, NULL, 0,
					     FALSE, NULL, &server_callbacks, ioloop);
	smtp_server_connection_start(conn);

	io_loop_run(ioloop);

	smtp_server_deinit(&smtp_server);
	timeout_remove(&to);
	io_loop_destroy(&ioloop);
}
FUZZ_END
