/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "ioloop.h"
#include "smtp-server.h"

static void server_connection_destroy(void *context)
{
	struct fuzzer_context *ctx = context;
	io_loop_stop(ctx->ioloop);
}

static void test_server_continue(struct fuzzer_context *ctx)
{
	//instead of simple io_loop_stop so as to free input io
	io_loop_stop_delayed(ctx->ioloop);
}

FUZZ_BEGIN_FD
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
	struct timeout *to;

	to = timeout_add_short(0, test_server_continue, &fuzz_ctx);
	smtp_server = smtp_server_init(&smtp_server_set);

	conn = smtp_server_connection_create(smtp_server, fuzz_ctx.fd, fuzz_ctx.fd, NULL, 0,
					     FALSE, NULL, &server_callbacks, &fuzz_ctx);
	smtp_server_connection_start(conn);

	io_loop_run(fuzz_ctx.ioloop);

	smtp_server_deinit(&smtp_server);
	timeout_remove(&to);
}
FUZZ_END
