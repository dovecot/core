/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-pump.h"
#include "fuzzer.h"

#include <sys/socket.h>

void fuzzer_init(void)
{
	if (!lib_is_initialized()) {
		lib_init();
		lib_signals_init();
		lib_signals_ignore(SIGPIPE, TRUE);
	}
}

static void pump_finished(enum iostream_pump_status status ATTR_UNUSED,
			  struct iostream_pump *pump)
{
	struct ostream *output = iostream_pump_get_output(pump);

	if (shutdown(o_stream_get_fd(output), SHUT_RDWR) < 0)
		i_fatal("shutdown() failed: %m");
	iostream_pump_destroy(&pump);
}

int fuzzer_io_as_fd(const uint8_t *data, size_t size)
{
	int sfd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) < 0)
		i_fatal("socketpair() failed: %m");
	net_set_nonblock(sfd[0], TRUE);
	net_set_nonblock(sfd[1], TRUE);

	struct istream *input = i_stream_create_from_data(data, size);
	struct ostream *output = o_stream_create_fd_autoclose(&sfd[0], IO_BLOCK_SIZE);
	struct iostream_pump *pump = iostream_pump_create(input, output);
	iostream_pump_set_completion_callback(pump, pump_finished, pump);
	i_stream_unref(&input);
	o_stream_unref(&output);
	iostream_pump_start(pump);
	return sfd[1];
}
