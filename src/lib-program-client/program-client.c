/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "istream-private.h"
#include "ostream-dot.h"
#include "istream-dot.h"
#include "ostream.h"
#include "iostream-pump.h"
#include "iostream-temp.h"
#include "lib-signals.h"

#include "program-client-private.h"

#include <unistd.h>

#define MAX_OUTPUT_BUFFER_SIZE 16384
#define MAX_OUTPUT_MEMORY_BUFFER (1024*128)

static void
program_client_callback(struct program_client *pclient, int result,
			void *context)
{
	program_client_callback_t *callback = pclient->callback;

	pclient->callback = NULL;
	if (pclient->destroying || callback == NULL)
		return;
	callback(result, context);
}

static void
program_client_timeout(struct program_client *pclient)
{
	i_error("program `%s' execution timed out (> %u msecs)",
		pclient->path, pclient->set.input_idle_timeout_msecs);
	program_client_fail(pclient, PROGRAM_CLIENT_ERROR_RUN_TIMEOUT);
}

static void
program_client_connect_timeout(struct program_client *pclient)
{
	i_error("program `%s' socket connection timed out (> %u msecs)",
		pclient->path, pclient->set.client_connect_timeout_msecs);
	program_client_fail(pclient, PROGRAM_CLIENT_ERROR_CONNECT_TIMEOUT);
}

static int
program_client_connect(struct program_client *pclient)
{
	if (pclient->set.client_connect_timeout_msecs != 0) {
		pclient->to = timeout_add(
			pclient->set.client_connect_timeout_msecs,
			program_client_connect_timeout, pclient);
	}

	return pclient->connect(pclient);
}

static int
program_client_close_output(struct program_client *pclient)
{
	int ret;

	o_stream_destroy(&pclient->program_output);
	o_stream_destroy(&pclient->raw_program_output);
	if ((ret = pclient->close_output(pclient)) < 0)
		return -1;

	return ret;
}

static void
program_client_disconnect_extra_fds(struct program_client *pclient)
{
	struct program_client_extra_fd *efds;
	unsigned int i, count;

	if (!array_is_created(&pclient->extra_fds))
		return;

	efds = array_get_modifiable(&pclient->extra_fds, &count);
	for(i = 0; i < count; i++) {
		i_stream_unref(&efds[i].input);
		io_remove(&efds[i].io);
		if (efds[i].parent_fd != -1 && close(efds[i].parent_fd) < 0)
			i_error("close(fd=%d) failed: %m", efds[i].parent_fd);
	}
}

void program_client_disconnected(struct program_client *pclient)
{
	i_stream_destroy(&pclient->program_input);
	o_stream_destroy(&pclient->program_output);
	i_stream_destroy(&pclient->raw_program_input);
	o_stream_destroy(&pclient->raw_program_output);

	timeout_remove(&pclient->to);
	io_remove(&pclient->io);
	iostream_pump_destroy(&pclient->pump_in);
	iostream_pump_destroy(&pclient->pump_out);

	if (pclient->fd_in != -1 && close(pclient->fd_in) < 0)
		i_error("close(%s) failed: %m", pclient->path);
	if (pclient->fd_out != -1 && pclient->fd_out != pclient->fd_in
	    && close(pclient->fd_out) < 0)
		i_error("close(%s/out) failed: %m", pclient->path);
	pclient->fd_in = pclient->fd_out = -1;

	pclient->disconnected = TRUE;

	if (pclient->other_error &&
	    pclient->error == PROGRAM_CLIENT_ERROR_NONE) {
		pclient->error = PROGRAM_CLIENT_ERROR_OTHER;
	}

	program_client_callback(pclient,
		(pclient->error != PROGRAM_CLIENT_ERROR_NONE ?
			-1 : (int)pclient->exit_code),
		pclient->context);
}

static void
program_client_disconnect(struct program_client *pclient, bool force)
{
	int ret;

	if (pclient->disconnected)
		return;
	pclient->disconnected = TRUE;

	timeout_remove(&pclient->to);
	io_remove(&pclient->io);
	iostream_pump_destroy(&pclient->pump_in);
	iostream_pump_destroy(&pclient->pump_out);

	if ((ret = program_client_close_output(pclient)) < 0)
		pclient->other_error = TRUE;

	program_client_disconnect_extra_fds(pclient);

	pclient->disconnect(pclient, force);
}

void program_client_fail(struct program_client *pclient,
			 enum program_client_error error)
{
	if (pclient->error != PROGRAM_CLIENT_ERROR_NONE)
		return;

	pclient->error = error;
	program_client_disconnect(pclient, TRUE);
}

static bool
program_client_input_pending(struct program_client *pclient)
{
	struct program_client_extra_fd *efds = NULL;
	unsigned int count, i;

	if (pclient->pump_in != NULL || pclient->pump_out != NULL)
		return TRUE;

	if (pclient->program_output != NULL &&
	    !pclient->program_output->closed &&
	    o_stream_get_buffer_used_size(pclient->program_output) > 0) {
		return TRUE;
	}
	if (pclient->program_input != NULL &&
	    !pclient->program_input->closed &&
	    i_stream_have_bytes_left(pclient->program_input)) {
		return TRUE;
	}

	if (array_is_created(&pclient->extra_fds)) {
		efds = array_get_modifiable(&pclient->extra_fds, &count);
		for(i = 0; i < count; i++) {
			if (efds[i].input != NULL &&
			    !efds[i].input->closed &&
			    i_stream_have_bytes_left(efds[i].input)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

static void
program_client_output_finished(struct program_client *pclient)
{
	/* check whether program i/o is finished */
	if (!program_client_input_pending(pclient)) {
		/* finished */
		program_client_disconnect(pclient, FALSE);
	/* close output towards program, so that it reads EOF */
	} else if (program_client_close_output(pclient) < 0) {
		program_client_fail(pclient,
				    PROGRAM_CLIENT_ERROR_OTHER);
	}
}

static int
program_client_output_finish(struct program_client *pclient)
{
        struct ostream *output = pclient->program_output;
	int ret = 0;

	/* flush the output */
	if ((ret=o_stream_finish(output)) < 0) {
		i_error("write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return -1;
	}
	if (ret > 0)
		program_client_output_finished(pclient);
	return ret;
}

static void
program_client_output_pump_finished(enum iostream_pump_status status,
				    struct program_client *pclient)
{
	struct istream *input = pclient->input;
	struct ostream *output = pclient->program_output;

	i_assert(input != NULL);
	i_assert(output != NULL);

	switch (status) {
	case IOSTREAM_PUMP_STATUS_INPUT_EOF:
		break;
	case IOSTREAM_PUMP_STATUS_INPUT_ERROR:
		i_error("read(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		i_error("write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	}

	iostream_pump_destroy(&pclient->pump_out);

	o_stream_set_flush_callback(pclient->program_output,
		program_client_output_finish, pclient);
	o_stream_set_flush_pending(pclient->program_output, TRUE);
}

static void
program_client_input_finished(struct program_client *pclient)
{
	/* check whether program i/o is finished */
	if (program_client_input_pending(pclient))
		return;

	/* finished */
	program_client_disconnect(pclient, FALSE);
}

static void
program_client_input_finish(struct program_client *pclient)
{
	struct istream *input = pclient->program_input;
	const unsigned char *data;
	size_t size;
	int ret;

	/* read (the remainder of) the raw program input */
	while ((ret=i_stream_read_more(input, &data, &size)) > 0)
		i_stream_skip(input, size);
	if (ret == 0)
		return;
	if (ret < 0) {
		if (input->stream_errno != 0) {
			i_error("read(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
			program_client_fail(pclient,
					    PROGRAM_CLIENT_ERROR_IO);
			return;
		}
	}

	if (pclient->program_input != pclient->raw_program_input) {
		/* return to raw program input */
		i_stream_unref(&pclient->program_input);
		pclient->program_input = pclient->raw_program_input;
		i_stream_ref(pclient->program_input);

		io_remove(&pclient->io);
		pclient->io = io_add_istream(pclient->program_input,
					     program_client_input_finish,
					     pclient);
		io_set_pending(pclient->io);
	}

	program_client_input_finished(pclient);
}

static void
program_client_input_pump_finished(enum iostream_pump_status status,
				   struct program_client *pclient)
{
	struct istream *input = pclient->program_input;
	struct ostream *output = pclient->output;

	i_assert(input != NULL);
	i_assert(output != NULL);

	switch (status) {
	case IOSTREAM_PUMP_STATUS_INPUT_EOF:
		break;
	case IOSTREAM_PUMP_STATUS_INPUT_ERROR:
		i_error("read(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		i_error("write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	}

	iostream_pump_destroy(&pclient->pump_in);

	if (pclient->program_input != pclient->raw_program_input) {
		/* return to raw program input */
		i_stream_unref(&pclient->program_input);
		pclient->program_input = pclient->raw_program_input;
		i_stream_ref(pclient->program_input);
	}

	i_assert(pclient->io == NULL);
	pclient->io = io_add_istream(pclient->program_input,
				     program_client_input_finish, pclient);
	io_set_pending(pclient->io);
}

static void
program_client_extra_fd_input(struct program_client_extra_fd *efd)
{
	struct program_client *pclient = efd->pclient;

	i_assert(efd->callback != NULL);
	efd->callback(efd->context, efd->input);

	if (efd->input->closed || !i_stream_have_bytes_left(efd->input)) {
		if (!program_client_input_pending(pclient))
			program_client_disconnect(pclient, FALSE);
	}
}

void program_client_connected(struct program_client *pclient)
{
	/* finish creating program input */
	if (pclient->raw_program_input != NULL) {
		struct istream *input = pclient->raw_program_input;

		/* initialize dot input stream if required */
		if (pclient->set.use_dotstream)
			input = i_stream_create_dot(input, FALSE);
		else
			i_stream_ref(input);
		pclient->program_input = input;
	}
	/* finish creating program output */
	if (pclient->raw_program_output != NULL) {
		struct ostream *output = pclient->raw_program_output;

		/* initialize dot output stream if required */
		if (pclient->set.use_dotstream)
			output = o_stream_create_dot(output, FALSE);
		else
			o_stream_ref(output);
		pclient->program_output = output;
	}

	pclient->start_time = ioloop_timeval;
	timeout_remove(&pclient->to);
	if (pclient->set.input_idle_timeout_msecs != 0) {
		pclient->to =
			timeout_add(pclient->set.input_idle_timeout_msecs,
				    program_client_timeout, pclient);
	}

	/* run program input */
	if (pclient->program_input == NULL) {
		/* nothing */
	} else if (pclient->output == NULL) {
		i_assert(pclient->io == NULL);
		pclient->io = io_add_istream(pclient->program_input,
					     program_client_input_finish,
					     pclient);
		io_set_pending(pclient->io);
	} else {
		pclient->pump_in =
			iostream_pump_create(pclient->program_input,
					     pclient->output);
		iostream_pump_set_completion_callback(pclient->pump_in,
			program_client_input_pump_finished, pclient);
		iostream_pump_start(pclient->pump_in);
	}

	/* run program output */
	if (pclient->program_output == NULL) {
		/* nothing */
	} else if (pclient->input == NULL) {
		o_stream_set_flush_callback(pclient->program_output,
			program_client_output_finish, pclient);
		o_stream_set_flush_pending(pclient->program_output, TRUE);
	} else {
		pclient->pump_out =
			iostream_pump_create(pclient->input,
					     pclient->program_output);
		iostream_pump_set_completion_callback(pclient->pump_out,
			program_client_output_pump_finished, pclient);
		iostream_pump_start(pclient->pump_out);
	}
}

void program_client_init(struct program_client *pclient, pool_t pool,
			 const char *path,
			 const char *const *args,
			 const struct program_client_settings *set)
{
	pclient->pool = pool;
	pclient->path = p_strdup(pool, path);
	if (args != NULL)
		pclient->args = p_strarray_dup(pool, args);
	pclient->set = *set;
	pclient->debug = set->debug;
	pclient->fd_in = -1;
	pclient->fd_out = -1;
}

void program_client_set_input(struct program_client *pclient,
			      struct istream *input)
{
	i_stream_unref(&pclient->input);
	if (input != NULL)
		i_stream_ref(input);
	pclient->input = input;
}

void program_client_set_output(struct program_client *pclient,
			       struct ostream *output)
{
	o_stream_unref(&pclient->output);
	if (output != NULL)
		o_stream_ref(output);
	pclient->output = output;
	pclient->output_seekable = FALSE;
}

void program_client_set_output_seekable(struct program_client *pclient,
					const char *temp_prefix)
{
	o_stream_unref(&pclient->output);
	pclient->output = iostream_temp_create_sized(temp_prefix, 0,
		"(program client seekable output)",
		MAX_OUTPUT_MEMORY_BUFFER);
	pclient->output_seekable = TRUE;
}

struct istream *
program_client_get_output_seekable(struct program_client *pclient)
{
	i_assert(pclient->output_seekable);
	return iostream_temp_finish(&pclient->output, IO_BLOCK_SIZE);
}

#undef program_client_set_extra_fd
void program_client_set_extra_fd(struct program_client *pclient, int fd,
				 program_client_fd_callback_t *callback,
				 void *context)
{
	struct program_client_extra_fd *efds;
	struct program_client_extra_fd *efd = NULL;
	unsigned int i, count;
	i_assert(fd > 1);

	if (!array_is_created(&pclient->extra_fds))
		p_array_init(&pclient->extra_fds, pclient->pool, 2);

	efds = array_get_modifiable(&pclient->extra_fds, &count);
	for(i = 0; i < count; i++) {
		if (efds[i].child_fd == fd) {
			efd = &efds[i];
			break;
		}
	}

	if (efd == NULL) {
		efd = array_append_space(&pclient->extra_fds);
		efd->pclient = pclient;
		efd->child_fd = fd;
		efd->parent_fd = -1;
	}
	efd->callback = callback;
	efd->context = context;
}

void program_client_set_env(struct program_client *pclient, const char *name,
			    const char *value)
{
	const char *env;

	if (!array_is_created(&pclient->envs))
		p_array_init(&pclient->envs, pclient->pool, 16);

	env = p_strdup_printf(pclient->pool, "%s=%s", name, value);
	array_append(&pclient->envs, &env, 1);
}

void program_client_init_streams(struct program_client *pclient)
{
	/* Create streams for normal program I/O */
	if (pclient->fd_out >= 0) {
		struct ostream *program_output;

		program_output = o_stream_create_fd(pclient->fd_out,
						    MAX_OUTPUT_BUFFER_SIZE);
		o_stream_set_name(program_output, "program stdin");
		o_stream_set_no_error_handling(program_output, TRUE);
		pclient->raw_program_output = program_output;
	}
	if (pclient->fd_in >= 0) {
		struct istream *program_input;

		program_input = i_stream_create_fd(pclient->fd_in, (size_t)-1);
		i_stream_set_name(program_input, "program stdout");
		pclient->raw_program_input = program_input;
	}

	/* Create streams for additional output through side-channel fds */
	if (array_is_created(&pclient->extra_fds)) {
		struct program_client_extra_fd *efds = NULL;
		unsigned int count, i;

		efds = array_get_modifiable(&pclient->extra_fds, &count);
		for(i = 0; i < count; i++) {
			i_assert(efds[i].parent_fd >= 0);
			efds[i].input = i_stream_create_fd
				(efds[i].parent_fd, (size_t)-1);
			i_stream_set_name(efds[i].input,
				t_strdup_printf("program output fd=%d",
						efds[i].child_fd));
			efds[i].io = io_add(efds[i].parent_fd, IO_READ,
					    program_client_extra_fd_input,
					    &efds[i]);
		}
	}
}

void program_client_destroy(struct program_client **_pclient)
{
	struct program_client *pclient = *_pclient;

	*_pclient = NULL;

	pclient->destroying = TRUE;
	pclient->callback = NULL;

	program_client_disconnect(pclient, TRUE);

	i_assert(pclient->callback == NULL);

	i_stream_unref(&pclient->input);
	o_stream_unref(&pclient->output);

	i_stream_unref(&pclient->program_input);
	o_stream_unref(&pclient->program_output);
	i_stream_unref(&pclient->raw_program_input);
	o_stream_unref(&pclient->raw_program_output);

	if (pclient->destroy != NULL)
		pclient->destroy(pclient);

	pool_unref(&pclient->pool);
}

void program_client_switch_ioloop(struct program_client *pclient)
{
	if (pclient->input != NULL)
		i_stream_switch_ioloop(pclient->input);
	if (pclient->program_input != NULL)
		i_stream_switch_ioloop(pclient->program_input);
	if (pclient->output != NULL)
		o_stream_switch_ioloop(pclient->output);
	if (pclient->program_output != NULL)
		o_stream_switch_ioloop(pclient->program_output);
	if (pclient->to != NULL)
		pclient->to = io_loop_move_timeout(&pclient->to);
	if (pclient->pump_in != NULL)
		iostream_pump_switch_ioloop(pclient->pump_in);
	if (pclient->pump_out != NULL)
		iostream_pump_switch_ioloop(pclient->pump_out);
	if (pclient->io != NULL)
		pclient->io = io_loop_move_io(&pclient->io);
	pclient->switch_ioloop(pclient);
}

int program_client_create(const char *uri, const char *const *args,
			  const struct program_client_settings *set,
			  bool noreply, struct program_client **pc_r,
			  const char **error_r)
{
	if (str_begins(uri, "exec:")) {
		*pc_r = program_client_local_create(uri+5, args, set);
		return 0;
	} else if (str_begins(uri, "unix:")) {
		*pc_r = program_client_unix_create(uri+5, args, set, noreply);
		return 0;
	} else if (str_begins(uri, "tcp:")) {
		const char *host;
		in_port_t port;

		if (net_str2hostport(uri+4, 0, &host, &port) < 0 ||
		    port == 0) {
			*error_r = t_strdup_printf(
				"Invalid tcp syntax, "
				"must be host:port in '%s'", uri+4);
			return -1;
		}
		*pc_r = program_client_net_create(host, port, args, set,
						  noreply);
		return 0;
	} else {
		*error_r = t_strdup_printf(
			"Unsupported program client scheme '%s'",
			t_strcut(uri, ':'));
		return -1;
	}
}

static void
program_client_run_callback(int result, int *context)
{
	*context = result;
	io_loop_stop(current_ioloop);
}

int program_client_run(struct program_client *pclient)
{
	int ret = -2;
	struct ioloop *prev_ioloop = current_ioloop;
	struct ioloop *ioloop = io_loop_create();

	program_client_switch_ioloop(pclient);

	program_client_run_async(pclient, program_client_run_callback, &ret);

	if (ret == -2) {
		io_loop_run(ioloop);
	}

	io_loop_set_current(prev_ioloop);
	program_client_switch_ioloop(pclient);
	io_loop_set_current(ioloop);
	io_loop_destroy(&ioloop);

	if (pclient->error != PROGRAM_CLIENT_ERROR_NONE)
		return -1;

	return (int)pclient->exit_code;
}

#undef program_client_run_async
void program_client_run_async(struct program_client *pclient,
			      program_client_callback_t *callback,
			      void *context)
{
	i_assert(callback != NULL);

	pclient->disconnected = FALSE;
	pclient->exit_code = PROGRAM_CLIENT_EXIT_SUCCESS;
	pclient->error = PROGRAM_CLIENT_ERROR_NONE;

	pclient->callback = callback;
	pclient->context = context;
	if (program_client_connect(pclient) < 0)
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
}
