/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-mkstemp.h"
#include "istream-private.h"
#include "ostream-dot.h"
#include "istream-dot.h"
#include "ostream.h"
#include "iostream-pump.h"
#include "iostream-temp.h"
#include "lib-signals.h"
#include "settings.h"
#include "settings-parser.h"

#include "program-client-private.h"

#include <unistd.h>

#define MAX_OUTPUT_BUFFER_SIZE 16384
#define MAX_OUTPUT_MEMORY_BUFFER (1024*128)

static bool program_client_settings_check(void *_set, pool_t pool,
					  const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct program_client_settings)
static const struct setting_define program_client_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "execute",
	  .offset = offsetof(struct program_client_settings, execute),
	  .filter_array_field_name = "execute_name", },
	DEF(STR, execute_name),
	DEF(ENUM, execute_driver),
	DEF(STR, execute_args),

	DEF(STR, execute_fork_path),
	DEF(STR, execute_unix_socket_path),
	DEF(STR, execute_tcp_host),
	DEF(IN_PORT, execute_tcp_port),

	SETTING_DEFINE_STRUCT_STR_HIDDEN("base_dir", base_dir,
					 struct program_client_settings),

	SETTING_DEFINE_LIST_END
};

static const struct program_client_settings program_client_default_settings = {
	.execute = ARRAY_INIT,
	.execute_name = "",
	.execute_driver = "unix:fork:tcp",
	.execute_args = "",

	.execute_fork_path = "",
	.execute_unix_socket_path = "",
	.execute_tcp_host = "",
	.execute_tcp_port = 0,

	.base_dir = PKG_RUNDIR,
};
const struct setting_parser_info program_client_setting_parser_info = {
	.name = "execute",

	.defines = program_client_setting_defines,
	.defaults = &program_client_default_settings,

	.struct_size = sizeof(struct program_client_settings),
	.pool_offset1 = 1 + offsetof(struct program_client_settings, pool),

	.check_func = program_client_settings_check,
};

void program_client_set_label(struct program_client *pclient,
			      const char *label)
{
	event_set_append_log_prefix(pclient->event,
		t_strconcat("execute ", label, ": ", NULL));
}

static void
program_client_callback(struct program_client *pclient, int result,
			void *context)
{
	program_client_callback_t *callback = pclient->callback;

	pclient->callback = NULL;
	if (pclient->destroying || callback == NULL)
		return;
	if (pclient->wait_ioloop != NULL)
		io_loop_stop(pclient->wait_ioloop);
	callback(result, context);
}

static void
program_client_timeout(struct program_client *pclient)
{
	e_error(pclient->event,
		"Execution timed out (> %u msecs)",
		pclient->params.input_idle_timeout_msecs);
	program_client_fail(pclient, PROGRAM_CLIENT_ERROR_RUN_TIMEOUT);
}

static void
program_client_connect_timeout(struct program_client *pclient)
{
	e_error(pclient->event,
		"Connection timed out (> %u msecs)",
		pclient->params.client_connect_timeout_msecs);
	program_client_fail(pclient, PROGRAM_CLIENT_ERROR_CONNECT_TIMEOUT);
}

static int
program_client_connect(struct program_client *pclient)
{
	e_debug(pclient->event, "Establishing connection");

	if (pclient->params.client_connect_timeout_msecs != 0) {
		pclient->to = timeout_add(
			pclient->params.client_connect_timeout_msecs,
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
		if (efds[i].parent_fd != -1)
			i_close_fd(&efds[i].parent_fd);
	}

	array_clear(&pclient->extra_fds);
}

static void
program_client_do_disconnect(struct program_client *pclient)
{
	i_stream_destroy(&pclient->program_input);
	o_stream_destroy(&pclient->program_output);
	i_stream_destroy(&pclient->raw_program_input);
	o_stream_destroy(&pclient->raw_program_output);

	timeout_remove(&pclient->to);
	io_remove(&pclient->io);
	iostream_pump_destroy(&pclient->pump_in);
	iostream_pump_destroy(&pclient->pump_out);

	if (pclient->fd_out == pclient->fd_in)
		pclient->fd_in = -1;
	i_close_fd(&pclient->fd_in);
	i_close_fd(&pclient->fd_out);

	program_client_disconnect_extra_fds(pclient);

	if (!pclient->disconnected)
		e_debug(pclient->event, "Disconnected");
	pclient->disconnected = TRUE;
}

void program_client_disconnected(struct program_client *pclient)
{
	program_client_do_disconnect(pclient);

	if (pclient->other_error &&
	    pclient->error == PROGRAM_CLIENT_ERROR_NONE) {
		pclient->error = PROGRAM_CLIENT_ERROR_OTHER;
	}

	program_client_callback(pclient,
		(pclient->error != PROGRAM_CLIENT_ERROR_NONE ?
			PROGRAM_CLIENT_EXIT_STATUS_INTERNAL_FAILURE :
			pclient->exit_status),
		pclient->context);
}

static void
program_client_disconnect(struct program_client *pclient, bool force)
{
	if (pclient->disconnected)
		return;

	program_client_do_disconnect(pclient);
	pclient->disconnect(pclient, force);
}

void program_client_fail(struct program_client *pclient,
			 enum program_client_error error)
{
	if (pclient->error != PROGRAM_CLIENT_ERROR_NONE)
		return;

	e_debug(pclient->event, "Failed to run program");

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
	e_debug(pclient->event, "Finished input to program");

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
		e_error(pclient->event,
			"write(%s) failed: %s",
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
		e_error(pclient->event,
			"read(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		e_error(pclient->event,
			"write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	}

	iostream_pump_destroy(&pclient->pump_out);

	e_debug(pclient->event, "Finished streaming payload to program");

	o_stream_set_flush_callback(pclient->program_output,
		program_client_output_finish, pclient);
	o_stream_set_flush_pending(pclient->program_output, TRUE);
}

static void
program_client_input_finished(struct program_client *pclient)
{
	e_debug(pclient->event, "Finished output from program");

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
			e_error(pclient->event,
				"read(%s) failed: %s",
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
		e_error(pclient->event,
			"read(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		e_error(pclient->event,
			"write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
		return;
	}

	iostream_pump_destroy(&pclient->pump_in);

	e_debug(pclient->event, "Finished streaming payload from program");

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
	e_debug(pclient->event, "Connected to program");

	/* finish creating program input */
	if (pclient->raw_program_input != NULL) {
		struct istream *input = pclient->raw_program_input;

		/* initialize dot input stream if required */
		if (pclient->params.use_dotstream)
			input = i_stream_create_dot(input, ISTREAM_DOT_TRIM_TRAIL |
							   ISTREAM_DOT_LOOSE_EOT);
		else
			i_stream_ref(input);
		pclient->program_input = input;
	}
	/* finish creating program output */
	if (pclient->raw_program_output != NULL) {
		struct ostream *output = pclient->raw_program_output;

		/* initialize dot output stream if required */
		if (pclient->params.use_dotstream)
			output = o_stream_create_dot(output, FALSE);
		else
			o_stream_ref(output);
		pclient->program_output = output;
	}

	pclient->start_time = ioloop_timeval;
	timeout_remove(&pclient->to);
	if (pclient->params.input_idle_timeout_msecs != 0) {
		pclient->to =
			timeout_add(pclient->params.input_idle_timeout_msecs,
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
			 struct event *event, const char *initial_label,
			 const char *const *args,
			 const struct program_client_parameters *params)
{
	pclient->pool = pool;
	pclient->event = event_create(event);
	if (args != NULL)
		pclient->args = p_strarray_dup(pool, args);
	pclient->fd_in = -1;
	pclient->fd_out = -1;

	if (params != NULL) {
		pclient->params = *params;
		pclient->params.dns_client_socket_path =
			p_strdup(pool, params->dns_client_socket_path);
	}

	program_client_set_label(pclient, initial_label);

	e_debug(pclient->event, "Created (args=%s)",
		t_strarray_join(args, " "));
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
	array_push_back(&pclient->envs, &env);

	e_debug(pclient->event, "Pass environment: %s",
		str_sanitize(env, 256));
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

		program_input = i_stream_create_fd(pclient->fd_in, SIZE_MAX);
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
				(efds[i].parent_fd, SIZE_MAX);
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

	e_debug(pclient->event, "Destroy");

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

	event_unref(&pclient->event);

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

int program_client_create(struct event *event, const char *uri,
			  const char *const *args,
			  const struct program_client_parameters *params,
			  struct program_client **pc_r, const char **error_r)
{
	const char *suffix;

	if (str_begins(uri, "exec:", &suffix)) {
		*pc_r = program_client_local_create(event, suffix, args, params);
		return 0;
	} else if (str_begins(uri, "unix:", &suffix)) {
		*pc_r = program_client_unix_create(event, suffix, args, params);
		return 0;
	} else if (str_begins(uri, "tcp:", &suffix)) {
		const char *host;
		in_port_t port;

		if (net_str2hostport(suffix, 0, &host, &port) < 0 ||
		    port == 0) {
			*error_r = t_strdup_printf(
				"Invalid tcp syntax, "
				"must be host:port in '%s'", suffix);
			return -1;
		}
		*pc_r = program_client_net_create(event, host, port, args, params);
		return 0;
	} else {
		*error_r = t_strdup_printf(
			"Unsupported program client scheme '%s'",
			t_strcut(uri, ':'));
		return -1;
	}
}

static bool
program_client_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct program_client_settings *set = _set;

	if (strcmp(set->execute_driver, "unix") == 0) {
		if (set->execute_unix_socket_path[0] == '\0')
			set->execute_unix_socket_path = set->execute_name;
		if (set->execute_unix_socket_path[0] != '/') {
			set->execute_unix_socket_path = p_strconcat(pool,
				set->base_dir, "/",
				set->execute_unix_socket_path, NULL);
		}
	} else if (strcmp(set->execute_driver, "fork") == 0) {
		if (set->execute_fork_path[0] == '\0')
			set->execute_fork_path = set->execute_name;
	} else if (strcmp(set->execute_driver, "tcp") == 0) {
		if (set->execute_tcp_host[0] == '\0' &&
		    set->execute_name[0] != '\0') {
			const char *host;
			if (net_str2hostport(set->execute_name, 0, &host,
					     &set->execute_tcp_port) < 0) {
				*error_r = t_strdup_printf(
					"Failed to parse execute_tcp_host:port from execute_name=%s",
					set->execute_name);
				return FALSE;
			}
			set->execute_tcp_host = p_strdup(pool, host);
		}
		if (set->execute_tcp_port == 0) {
			*error_r = "execute_tcp_port must not be 0 with execute_driver=tcp";
			return FALSE;
		}
	}
	return TRUE;
}

static int
program_client_create_filter_auto(struct event *event, const char *execute_name,
				  const struct program_client_parameters *params,
				  struct program_client **pc_r, const char **error_r)
{
	const struct program_client_settings *set;

	/* Get settings for the first execute list filter */
	event = event_create(event);
	if (settings_get_filter(event, "execute", execute_name,
				&program_client_setting_parser_info, 0,
				&set, error_r) < 0) {
		event_unref(&event);
		return -1;
	}

	const char *const *args = t_strsplit_spaces(set->execute_args, " ");
	if (params->append_args != NULL) {
		ARRAY_TYPE(const_string) new_args;
		t_array_init(&new_args, 8);
		array_append(&new_args, args, str_array_length(args));
		array_append(&new_args, params->append_args,
			     str_array_length(params->append_args));
		array_append_zero(&new_args);
		args = array_front(&new_args);
	}
	if (strcmp(set->execute_driver, "unix") == 0) {
		*pc_r = program_client_unix_create(event,
				set->execute_unix_socket_path, args, params);
	} else if (strcmp(set->execute_driver, "fork") == 0) {
		*pc_r = program_client_local_create(event,
				set->execute_fork_path, args, params);
	} else if (strcmp(set->execute_driver, "tcp") == 0) {
		*pc_r = program_client_net_create(event, set->execute_tcp_host,
						  set->execute_tcp_port,
						  args, params);
	} else {
		/* should have been caught by settings enum checking already */
		i_unreached();
	}

	event_unref(&event);
	settings_free(set);
	return 0;
}

int program_client_create_auto(struct event *event,
			       const struct program_client_parameters *params,
			       struct program_client **pc_r, const char **error_r)
{
	struct program_client_settings *set;

	i_assert(event != NULL);

	if (settings_get(event, &program_client_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;
	if (array_is_empty(&set->execute)) {
		*error_r = "execute { .. } named list filter is missing";
		settings_free(set);
		return 0;
	}
	const char *execute_name_first =
		t_strdup(array_idx_elem(&set->execute, 0));
	if (array_count(&set->execute) > 1) {
		/* Only one execution supported for now. */
		const char *execute_name_extra =
			array_idx_elem(&set->execute, 1);
		*error_r = t_strdup_printf(
				"Extra execute %s { .. } named list filter - "
				"only one execution is allowed for now "
				"(previous: execute %s { .. })",
				execute_name_extra, execute_name_first);
		settings_free(set);
		return -1;
	}
	settings_free(set);

	if (program_client_create_filter_auto(event, execute_name_first,
					      params, pc_r, error_r) < 0)
		return -1;
	return 1;
}

static void
program_client_run_callback(int result, int *context)
{
	*context = result;
	io_loop_stop(current_ioloop);
}

enum program_client_exit_status program_client_run(struct program_client *pclient)
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
		return PROGRAM_CLIENT_EXIT_STATUS_INTERNAL_FAILURE;

	return pclient->exit_status;
}

#undef program_client_run_async
void program_client_run_async(struct program_client *pclient,
			      program_client_callback_t *callback,
			      void *context)
{
	i_assert(callback != NULL);

	pclient->disconnected = FALSE;
	pclient->exit_status = PROGRAM_CLIENT_EXIT_STATUS_SUCCESS;
	pclient->error = PROGRAM_CLIENT_ERROR_NONE;

	pclient->callback = callback;
	pclient->context = context;
	if (program_client_connect(pclient) < 0)
		program_client_fail(pclient, PROGRAM_CLIENT_ERROR_IO);
}

void program_client_wait(struct program_client *pclient)
{
	if (pclient->disconnected)
		return;

	struct ioloop *prev_ioloop = current_ioloop;
	struct ioloop *ioloop = io_loop_create();

	program_client_switch_ioloop(pclient);

	pclient->wait_ioloop = ioloop;
	io_loop_run(ioloop);
	pclient->wait_ioloop = NULL;

	io_loop_set_current(prev_ioloop);
	program_client_switch_ioloop(pclient);
	io_loop_set_current(ioloop);
	io_loop_destroy(&ioloop);
}
