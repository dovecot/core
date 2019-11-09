/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "iostream-pump.h"
#include "istream.h"
#include "ostream.h"
#include <unistd.h>

#undef iostream_pump_set_completion_callback

struct iostream_pump {
	int refcount;

	struct istream *input;
	struct ostream *output;

	struct io *io;

	iostream_pump_callback_t *callback;
	void *context;

	bool waiting_output;
	bool completed;
};

static void iostream_pump_copy(struct iostream_pump *pump)
{
	enum ostream_send_istream_result res;
	size_t old_size;

	o_stream_cork(pump->output);
	old_size = o_stream_get_max_buffer_size(pump->output);
	o_stream_set_max_buffer_size(pump->output,
		I_MIN(IO_BLOCK_SIZE,
		      o_stream_get_max_buffer_size(pump->output)));
	res = o_stream_send_istream(pump->output, pump->input);
	o_stream_set_max_buffer_size(pump->output, old_size);
	o_stream_uncork(pump->output);

	switch(res) {
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		io_remove(&pump->io);
		pump->callback(IOSTREAM_PUMP_STATUS_INPUT_ERROR,
			       pump->context);
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		io_remove(&pump->io);
		pump->callback(IOSTREAM_PUMP_STATUS_OUTPUT_ERROR,
			       pump->context);
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		i_assert(!pump->output->blocking);
		pump->waiting_output = TRUE;
		io_remove(&pump->io);
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		pump->waiting_output = FALSE;
		io_remove(&pump->io);
		/* flush it */
		switch (o_stream_flush(pump->output)) {
		case -1:
			pump->callback(IOSTREAM_PUMP_STATUS_OUTPUT_ERROR,
				       pump->context);
			break;
		case 0:
			pump->waiting_output = TRUE;
			pump->completed = TRUE;
			break;
		default:
			pump->callback(IOSTREAM_PUMP_STATUS_INPUT_EOF,
				       pump->context);
			break;
		}
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_assert(!pump->input->blocking);
		pump->waiting_output = FALSE;
		return;
	}
	i_unreached();
}

static int iostream_pump_flush(struct iostream_pump *pump)
{
	int ret;

	if ((ret = o_stream_flush(pump->output)) <= 0) {
		if (ret < 0) {
			pump->callback(IOSTREAM_PUMP_STATUS_OUTPUT_ERROR,
				       pump->context);
		}
		return ret;
	}
	pump->waiting_output = FALSE;
	if (pump->completed) {
		pump->callback(IOSTREAM_PUMP_STATUS_INPUT_EOF, pump->context);
		return 1;
	}

	if (pump->input->blocking)
		iostream_pump_copy(pump);
	else if (pump->io == NULL) {
		pump->io = io_add_istream(pump->input,
					  iostream_pump_copy, pump);
		io_set_pending(pump->io);
	}
	return ret;
}

struct iostream_pump *
iostream_pump_create(struct istream *input, struct ostream *output)
{
	struct iostream_pump *pump;

	i_assert(input != NULL &&
		 output != NULL);
	i_assert(!input->blocking || !output->blocking);

	/* ref streams */
	i_stream_ref(input);
	o_stream_ref(output);

	/* create pump */
	pump = i_new(struct iostream_pump, 1);
	pump->refcount = 1;
	pump->input = input;
	pump->output = output;

	return pump;
}

void iostream_pump_start(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	i_assert(pump->callback != NULL);

	/* add flush handler */
	if (!pump->output->blocking) {
		o_stream_set_flush_callback(pump->output,
					    iostream_pump_flush, pump);
	}

	/* make IO objects */
	if (pump->input->blocking) {
		i_assert(!pump->output->blocking);
		o_stream_set_flush_pending(pump->output, TRUE);
	} else {
		pump->io = io_add_istream(pump->input,
					  iostream_pump_copy, pump);
		io_set_pending(pump->io);
	}
}

struct istream *iostream_pump_get_input(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	return pump->input;
}

struct ostream *iostream_pump_get_output(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	return pump->output;
}

void iostream_pump_set_completion_callback(struct iostream_pump *pump,
					   iostream_pump_callback_t *callback,
					   void *context)
{
	i_assert(pump != NULL);
	pump->callback = callback;
	pump->context = context;
}

void iostream_pump_ref(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	i_assert(pump->refcount > 0);
	pump->refcount++;
}

void iostream_pump_unref(struct iostream_pump **_pump)
{
	i_assert(_pump != NULL);
	struct iostream_pump *pump = *_pump;

	if (pump == NULL)
		return;

	i_assert(pump->refcount > 0);

	*_pump = NULL;

	if (--pump->refcount > 0)
		return;

	iostream_pump_stop(pump);

	o_stream_unref(&pump->output);
	i_stream_unref(&pump->input);
	i_free(pump);
}

void iostream_pump_destroy(struct iostream_pump **_pump)
{
	i_assert(_pump != NULL);
	struct iostream_pump *pump = *_pump;

	if (pump == NULL)
		return;

	*_pump = NULL;

	iostream_pump_stop(pump);
	o_stream_unref(&pump->output);
	i_stream_unref(&pump->input);

	iostream_pump_unref(&pump);
}

void iostream_pump_stop(struct iostream_pump *pump)
{
	i_assert(pump != NULL);

	if (pump->output != NULL)
		o_stream_unset_flush_callback(pump->output);

	io_remove(&pump->io);
}

bool iostream_pump_is_waiting_output(struct iostream_pump *pump)
{
	return pump->waiting_output;
}

void iostream_pump_switch_ioloop_to(struct iostream_pump *pump,
				    struct ioloop *ioloop)
{
	i_assert(pump != NULL);
	if (pump->io != NULL)
		pump->io = io_loop_move_io_to(ioloop, &pump->io);
	o_stream_switch_ioloop_to(pump->output, ioloop);
	i_stream_switch_ioloop_to(pump->input, ioloop);
}

void iostream_pump_switch_ioloop(struct iostream_pump *pump)
{
	iostream_pump_switch_ioloop_to(pump, current_ioloop);
}
