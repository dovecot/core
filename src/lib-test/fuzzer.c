/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-pump.h"
#include "fuzzer.h"

#include <sys/socket.h>
#include <unistd.h>

void fuzzer_init(struct fuzzer_context *fuzz_ctx)
{
	i_zero(fuzz_ctx);
	if (!lib_is_initialized()) {
		lib_init();
		lib_signals_init();
		lib_signals_ignore(SIGPIPE, TRUE);
	}
	fuzz_ctx->fd = -1;
}

void fuzzer_deinit(struct fuzzer_context *fuzz_ctx)
{
	iostream_pump_destroy(&fuzz_ctx->pump);
	/* ensure fd gets closed, we don't care
	   if this fails. */
	if (fuzz_ctx->fd > -1)
		(void)close(fuzz_ctx->fd);
	if (fuzz_ctx->fd_pump > -1)
		(void)close(fuzz_ctx->fd_pump);
	if (fuzz_ctx->ioloop != NULL)
		io_loop_destroy(&fuzz_ctx->ioloop);
}

static void pump_finished(enum iostream_pump_status status ATTR_UNUSED,
			  struct fuzzer_context *fuzz_ctx)
{
	struct istream *input = iostream_pump_get_input(fuzz_ctx->pump);
	struct ostream *output = iostream_pump_get_output(fuzz_ctx->pump);

	switch (status) {
	case IOSTREAM_PUMP_STATUS_INPUT_EOF:
		break;
	case IOSTREAM_PUMP_STATUS_INPUT_ERROR:
		i_error("read(%s) failed: %s", i_stream_get_name(input),
			i_stream_get_error(input));
		break;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		i_error("write(%s) failed: %s", o_stream_get_name(output),
			o_stream_get_error(output));
		break;
	};

	if (shutdown(o_stream_get_fd(output), SHUT_WR) < 0)
		i_fatal("shutdown() failed: %m");
	iostream_pump_destroy(&fuzz_ctx->pump);
}

int fuzzer_io_as_fd(struct fuzzer_context *fuzz_ctx,
		   const uint8_t *data, size_t size)
{
	int sfd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) < 0)
		i_fatal("socketpair() failed: %m");
	net_set_nonblock(sfd[0], TRUE);
	net_set_nonblock(sfd[1], TRUE);

	struct istream *input = i_stream_create_from_data(data, size);
	struct ostream *output = o_stream_create_fd(sfd[0], IO_BLOCK_SIZE);
	i_stream_set_name(input, "(fuzzer data)");
	o_stream_set_name(output, "(fuzzer input to program)");
	o_stream_set_no_error_handling(output, TRUE);

	fuzz_ctx->pump = iostream_pump_create(input, output);
	fuzz_ctx->fd_pump = sfd[0];
	fuzz_ctx->fd = sfd[1];
	iostream_pump_set_completion_callback(fuzz_ctx->pump, pump_finished,
					      fuzz_ctx);
	i_stream_unref(&input);
	o_stream_unref(&output);
	iostream_pump_start(fuzz_ctx->pump);
	return sfd[1];
}


const char *fuzzer_t_strndup_replace_zero(
	const uint8_t *data, size_t size, char subst)
{
	char *out = t_malloc_no0(size + 1);
	for (size_t index = 0; index < size; ++index) {
		uint8_t ch = data[index];
		out[index] = ch == 0 ? subst : (char)ch;
	}
	out[size] = '\0';
	return out;
}