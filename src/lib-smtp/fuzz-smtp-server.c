/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "istream.h"
#include "ioloop.h"
#include "smtp-server.h"

static struct {
	struct istream *data_input;
} state = {
	.data_input = NULL,
};

static int
server_cmd_rcpt(void *conn_ctx ATTR_UNUSED,
		struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		struct smtp_server_recipient *rcpt ATTR_UNUSED)
{
	return 1;
}

static int
server_cmd_data_continue(void *conn_ctx ATTR_UNUSED,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_transaction *trans ATTR_UNUSED)
{
	struct istream *data_input = state.data_input;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	while ((ret = i_stream_read(data_input)) > 0 || ret == -2) {
		data = i_stream_get_data(data_input, &size);
		i_stream_skip(data_input, size);
		if (!smtp_server_cmd_data_check_size(cmd))
			return -1;
	}

	if (ret == 0)
		return 0;
	if (ret < 0 && data_input->stream_errno != 0) {
		/* Client probably disconnected */
		return -1;
	}

	smtp_server_reply_all(cmd, 250, "2.0.0", "Accepted");
	return 1;
}

static int
server_cmd_data_begin(void *conn_ctx ATTR_UNUSED,
		      struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		      struct smtp_server_transaction *trans ATTR_UNUSED,
		      struct istream *data_input)
{
	state.data_input = data_input;
	return 0;
}

static void server_connection_free(void *context)
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
		.conn_cmd_rcpt = server_cmd_rcpt,
		.conn_cmd_data_begin =  server_cmd_data_begin,
		.conn_cmd_data_continue = server_cmd_data_continue,
		.conn_free = server_connection_free,
	};
	struct smtp_server *smtp_server = NULL;
	struct timeout *to;

	to = timeout_add_short(10, test_server_continue, &fuzz_ctx);
	smtp_server = smtp_server_init(&smtp_server_set);

	conn = smtp_server_connection_create(smtp_server, fuzz_ctx.fd, fuzz_ctx.fd, NULL, 0,
					     FALSE, NULL, &server_callbacks, &fuzz_ctx);
	smtp_server_connection_start(conn);

	io_loop_run(fuzz_ctx.ioloop);

	smtp_server_deinit(&smtp_server);
	timeout_remove(&to);
}
FUZZ_END
