/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "iostream.h"
#include "net.h"
#include "strescape.h"
#include "llist.h"
#include "time-util.h"
#include "connection.h"

#include <unistd.h>

static void connection_idle_timeout(struct connection *conn)
{
	conn->disconnect_reason = CONNECTION_DISCONNECT_IDLE_TIMEOUT;
	conn->list->v.destroy(conn);
}

static void connection_connect_timeout(struct connection *conn)
{
	conn->disconnect_reason = CONNECTION_DISCONNECT_CONNECT_TIMEOUT;
	conn->list->v.destroy(conn);
}

void connection_input_default(struct connection *conn)
{
	const char *line;
	struct istream *input;
	struct ostream *output;
	int ret = 0;

	switch (connection_input_read(conn)) {
	case -1:
		return;
	case 0: /* allow calling this function for buffered input */
	case 1:
		break;
	default:
		i_unreached();
	}

	input = conn->input;
	output = conn->output;
	i_stream_ref(input);
	if (output != NULL) {
		o_stream_ref(output);
		o_stream_cork(output);
	}
	while (!input->closed && (line = i_stream_next_line(input)) != NULL) {
		T_BEGIN {
			ret = conn->list->v.input_line(conn, line);
		} T_END;
		if (ret <= 0)
			break;
	}
	if (output != NULL) {
		o_stream_uncork(output);
		o_stream_unref(&output);
	}
	if (ret < 0 && !input->closed) {
		conn->disconnect_reason = CONNECTION_DISCONNECT_DEINIT;
		conn->list->v.destroy(conn);
	}
	i_stream_unref(&input);
}

int connection_verify_version(struct connection *conn,
			      const char *const *args)
{
	unsigned int recv_major_version;

	/* VERSION <tab> service_name <tab> major version <tab> minor version */
	if (str_array_length(args) != 4 ||
	    strcmp(args[0], "VERSION") != 0 ||
	    str_to_uint(args[2], &recv_major_version) < 0 ||
	    str_to_uint(args[3], &conn->minor_version) < 0) {
		i_error("%s didn't reply with a valid VERSION line",
			conn->name);
		return -1;
	}

	if (strcmp(args[1], conn->list->set.service_name_in) != 0) {
		i_error("%s: Connected to wrong socket type. "
			"We want '%s', but received '%s'", conn->name,
			conn->list->set.service_name_in, args[1]);
		return -1;
	}

	if (recv_major_version != conn->list->set.major_version) {
		i_error("%s: Socket supports major version %u, "
			"but we support only %u (mixed old and new binaries?)",
			conn->name, recv_major_version,
			conn->list->set.major_version);
		return -1;
	}
	return 0;
}

int connection_input_line_default(struct connection *conn, const char *line)
{
	const char *const *args;

	args = t_strsplit_tabescaped(line);
	if (!conn->version_received) {
		if (connection_verify_version(conn, args) < 0)
			return -1;
		conn->version_received = TRUE;
		return 1;
	}
	if (args[0] == NULL && !conn->list->set.allow_empty_args_input) {
		i_error("%s: Unexpectedly received empty line", conn->name);
		return -1;
	}

	return conn->list->v.input_args(conn, args);
}

static void connection_init_streams(struct connection *conn)
{
	const struct connection_settings *set = &conn->list->set;

	i_assert(conn->io == NULL);
	i_assert(conn->input == NULL);
	i_assert(conn->output == NULL);
	i_assert(conn->to == NULL);

	conn->version_received = set->major_version == 0;

	if (set->input_max_size != 0) {
		conn->input = i_stream_create_fd(conn->fd_in,
						 set->input_max_size, FALSE);
		i_stream_set_name(conn->input, conn->name);
		conn->io = io_add_istream(conn->input, *conn->list->v.input, conn);
	} else {
		conn->io = io_add(conn->fd_in, IO_READ, *conn->list->v.input, conn);
	}
	if (set->output_max_size != 0) {
		conn->output = o_stream_create_fd(conn->fd_out,
						  set->output_max_size, FALSE);
		o_stream_set_no_error_handling(conn->output, TRUE);
		o_stream_set_name(conn->output, conn->name);
	}
	if (set->input_idle_timeout_secs != 0) {
		conn->to = timeout_add(set->input_idle_timeout_secs*1000,
				       connection_idle_timeout, conn);
	}
	if (set->major_version != 0 && !set->dont_send_version) {
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"VERSION\t%s\t%u\t%u\n", set->service_name_out,
			set->major_version, set->minor_version));
	}
}

static void connection_client_connected(struct connection *conn, bool success)
{
	i_assert(conn->list->set.client);

	conn->connect_finished = ioloop_timeval;
	if (success)
		connection_init_streams(conn);
	if (conn->list->v.client_connected != NULL)
		conn->list->v.client_connected(conn, success);
	if (!success) {
		conn->disconnect_reason =
			CONNECTION_DISCONNECT_CONN_CLOSED;
		conn->list->v.destroy(conn);
	}
}

void connection_init_server(struct connection_list *list,
			    struct connection *conn, const char *name,
			    int fd_in, int fd_out)
{
	i_assert(name != NULL);
	i_assert(!list->set.client);

	conn->list = list;
	conn->name = i_strdup(name);
	conn->fd_in = fd_in;
	conn->fd_out = fd_out;
	connection_init_streams(conn);

	DLLIST_PREPEND(&list->connections, conn);
	list->connections_count++;
}

void connection_init_client_ip(struct connection_list *list,
			       struct connection *conn,
			       const struct ip_addr *ip, in_port_t port)
{
	i_assert(list->set.client);

	conn->fd_in = conn->fd_out = -1;
	conn->list = list;
	conn->name = i_strdup_printf("%s:%u", net_ip2addr(ip), port);

	conn->ip = *ip;
	conn->port = port;

	DLLIST_PREPEND(&list->connections, conn);
	list->connections_count++;
}

void connection_init_client_unix(struct connection_list *list,
				 struct connection *conn, const char *path)
{
	i_assert(list->set.client);

	conn->fd_in = conn->fd_out = -1;
	conn->list = list;
	conn->name = i_strdup(path);

	DLLIST_PREPEND(&list->connections, conn);
	list->connections_count++;
}

void connection_init_from_streams(struct connection_list *list,
			    struct connection *conn, const char *name,
			    struct istream *input, struct ostream *output)
{
	i_assert(name != NULL);

	conn->list = list;
	conn->name = i_strdup(name);
	conn->fd_in = i_stream_get_fd(input);
	conn->fd_out = o_stream_get_fd(output);

	i_assert(conn->fd_in >= 0);
	i_assert(conn->fd_out >= 0);
	i_assert(conn->io == NULL);
	i_assert(conn->input == NULL);
	i_assert(conn->output == NULL);
	i_assert(conn->to == NULL);

	conn->input = input;
	i_stream_ref(conn->input);
	i_stream_set_name(conn->input, conn->name);

	conn->output = output;
	o_stream_ref(conn->output);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_set_name(conn->output, conn->name);

	conn->io = io_add_istream(conn->input, *list->v.input, conn);
	
	DLLIST_PREPEND(&list->connections, conn);
	list->connections_count++;

	if (list->v.client_connected != NULL)
		list->v.client_connected(conn, TRUE);
}

static void connection_socket_connected(struct connection *conn)
{
	io_remove(&conn->io);
	if (conn->to != NULL)
		timeout_remove(&conn->to);

	errno = net_geterror(conn->fd_in);
	connection_client_connected(conn, errno == 0);
}

int connection_client_connect(struct connection *conn)
{
	const struct connection_settings *set = &conn->list->set;
	int fd;

	i_assert(conn->list->set.client);
	i_assert(conn->fd_in == -1);

	if (conn->port != 0)
		fd = net_connect_ip(&conn->ip, conn->port, NULL);
	else if (conn->list->set.unix_client_connect_msecs == 0)
		fd = net_connect_unix(conn->name);
	else
		fd = net_connect_unix_with_retries(conn->name, conn->list->set.unix_client_connect_msecs);
	if (fd == -1)
		return -1;
	conn->fd_in = conn->fd_out = fd;
	conn->connect_started = ioloop_timeval;

	if (conn->port != 0 ||
	    conn->list->set.delayed_unix_client_connected_callback) {
		conn->io = io_add(conn->fd_out, IO_WRITE,
				  connection_socket_connected, conn);
		if (set->client_connect_timeout_msecs != 0) {
			conn->to = timeout_add(set->client_connect_timeout_msecs,
					       connection_connect_timeout, conn);
		}
	} else {
		connection_client_connected(conn, TRUE);
	}
	return 0;
}

void connection_disconnect(struct connection *conn)
{
	conn->last_input = 0;
	i_zero(&conn->last_input_tv);
	if (conn->to != NULL)
		timeout_remove(&conn->to);
	if (conn->io != NULL)
		io_remove(&conn->io);
	if (conn->input != NULL) {
		i_stream_close(conn->input);
		i_stream_destroy(&conn->input);
	}
	if (conn->output != NULL) {
		o_stream_close(conn->output);
		o_stream_destroy(&conn->output);
	}
	fd_close_maybe_stdio(&conn->fd_in, &conn->fd_out);
}

void connection_deinit(struct connection *conn)
{
	i_assert(conn->list->connections_count > 0);

	conn->list->connections_count--;
	DLLIST_REMOVE(&conn->list->connections, conn);

	connection_disconnect(conn);
	i_free(conn->name);
}

int connection_input_read(struct connection *conn)
{
	conn->last_input = ioloop_time;
	conn->last_input_tv = ioloop_timeval;
	if (conn->to != NULL)
		timeout_reset(conn->to);

	switch (i_stream_read(conn->input)) {
	case -2:
		/* buffer full */
		switch (conn->list->set.input_full_behavior) {
		case CONNECTION_BEHAVIOR_DESTROY:
			conn->disconnect_reason =
				CONNECTION_DISCONNECT_BUFFER_FULL;
			conn->list->v.destroy(conn);
			return -1;
		case CONNECTION_BEHAVIOR_ALLOW:
			return -2;
		}
		i_unreached();
	case -1:
		/* disconnected */
		conn->disconnect_reason =
			CONNECTION_DISCONNECT_CONN_CLOSED;
		conn->list->v.destroy(conn);
		return -1;
	case 0:
		/* nothing new read */
		return 0;
	default:
		/* something was read */
		return 1;
	}
}

const char *connection_disconnect_reason(struct connection *conn)
{
	switch (conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_DEINIT:
		return "Deinitializing";
	case CONNECTION_DISCONNECT_CONNECT_TIMEOUT: {
		unsigned int msecs =
			conn->list->set.client_connect_timeout_msecs;
		return t_strdup_printf("connect() timed out in %u.%03u secs",
				       msecs/1000, msecs%1000);
	}
	case CONNECTION_DISCONNECT_IDLE_TIMEOUT:
		return "Idle timeout";
	case CONNECTION_DISCONNECT_CONN_CLOSED:
		if (conn->input == NULL)
			return t_strdup_printf("connect() failed: %m");
		/* fall through */
	case CONNECTION_DISCONNECT_NOT:
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		return io_stream_get_disconnect_reason(conn->input, conn->output);
	}
	i_unreached();
}

const char *connection_input_timeout_reason(struct connection *conn)
{
	if (conn->last_input_tv.tv_sec != 0) {
		int diff = timeval_diff_msecs(&ioloop_timeval, &conn->last_input_tv);
		return t_strdup_printf("No input for %u.%03u secs",
				       diff/1000, diff%1000);
	} else if (conn->connect_finished.tv_sec != 0) {
		int diff = timeval_diff_msecs(&ioloop_timeval, &conn->connect_finished);
		return t_strdup_printf(
			"No input since connected %u.%03u secs ago",
			diff/1000, diff%1000);
	} else {
		int diff = timeval_diff_msecs(&ioloop_timeval, &conn->connect_started);
		return t_strdup_printf("connect() timed out after %u.%03u secs",
				       diff/1000, diff%1000);
	}
}

void connection_switch_ioloop(struct connection *conn)
{
	if (conn->io != NULL)
		conn->io = io_loop_move_io(&conn->io);
	if (conn->to != NULL)
		conn->to = io_loop_move_timeout(&conn->to);
	if (conn->input != NULL)
		i_stream_switch_ioloop(conn->input);
	if (conn->output != NULL)
		o_stream_switch_ioloop(conn->output);
}

struct connection_list *
connection_list_init(const struct connection_settings *set,
		     const struct connection_vfuncs *vfuncs)
{
	struct connection_list *list;

	i_assert(vfuncs->input != NULL ||
		 set->input_full_behavior != CONNECTION_BEHAVIOR_ALLOW);
	i_assert(set->major_version == 0 ||
		 (set->service_name_in != NULL &&
		  set->service_name_out != NULL));

	list = i_new(struct connection_list, 1);
	list->set = *set;
	list->v = *vfuncs;

	if (list->v.input == NULL)
		list->v.input = connection_input_default;
	if (list->v.input_line == NULL)
		list->v.input_line = connection_input_line_default;

	return list;
}

void connection_list_deinit(struct connection_list **_list)
{
	struct connection_list *list = *_list;
	struct connection *conn;

	*_list = NULL;

	while (list->connections != NULL) {
		conn = list->connections;
		conn->disconnect_reason = CONNECTION_DISCONNECT_DEINIT;
		list->v.destroy(conn);
		i_assert(conn != list->connections);
	}
	i_free(list);
}
