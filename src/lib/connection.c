/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-unix.h"
#include "ostream.h"
#include "ostream-unix.h"
#include "iostream.h"
#include "net.h"
#include "strescape.h"
#include "llist.h"
#include "time-util.h"
#include "connection.h"

#include <unistd.h>
#include <libgen.h>

static void connection_handshake_ready(struct connection *conn)
{
	conn->handshake_received = TRUE;
	if (conn->v.handshake_ready != NULL)
		conn->v.handshake_ready(conn);
}

static void connection_closed(struct connection *conn,
			      enum connection_disconnect_reason reason)
{
	conn->disconnect_reason = reason;
	conn->v.destroy(conn);
}

static void connection_idle_timeout(struct connection *conn)
{
	connection_closed(conn, CONNECTION_DISCONNECT_IDLE_TIMEOUT);
}

static void connection_connect_timeout(struct connection *conn)
{
	connection_closed(conn, CONNECTION_DISCONNECT_CONNECT_TIMEOUT);
}

void connection_input_default(struct connection *conn)
{
	const char *line;
	struct istream *input;
	struct ostream *output;
	int ret = 0;

	if (!conn->handshake_received &&
	    conn->v.handshake != NULL) {
		if ((ret = conn->v.handshake(conn)) < 0) {
			connection_closed(
				conn, CONNECTION_DISCONNECT_HANDSHAKE_FAILED);
			return;
		} else if (ret == 0) {
			return;
		} else {
			connection_handshake_ready(conn);
		}
	}

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
			if (!conn->handshake_received &&
			    conn->v.handshake_line != NULL) {
				ret = conn->v.handshake_line(conn, line);
				if (ret > 0)
					connection_handshake_ready(conn);
				else if (ret == 0)
					/* continue reading */
					ret = 1;
				else
					conn->disconnect_reason =
						CONNECTION_DISCONNECT_HANDSHAKE_FAILED;
			} else {
				ret = conn->v.input_line(conn, line);
			}
		} T_END;
		if (ret <= 0)
			break;
	}
	if (output != NULL) {
		o_stream_uncork(output);
		o_stream_unref(&output);
	}
	if (ret < 0 && !input->closed) {
		enum connection_disconnect_reason reason =
			conn->disconnect_reason;
		if (reason == CONNECTION_DISCONNECT_NOT)
			reason = CONNECTION_DISCONNECT_DEINIT;
		connection_closed(conn, reason);
	}
	i_stream_unref(&input);
}

int connection_verify_version(struct connection *conn,
			      const char *service_name,
			      unsigned int major_version,
			      unsigned int minor_version)
{
	i_assert(!conn->version_received);

	if (strcmp(service_name, conn->list->set.service_name_in) != 0) {
		e_error(conn->event, "Connected to wrong socket type. "
			"We want '%s', but received '%s'",
			conn->list->set.service_name_in, service_name);
		return -1;
	}

	if (major_version != conn->list->set.major_version) {
		e_error(conn->event, "Socket supports major version %u, "
			"but we support only %u (mixed old and new binaries?)",
			major_version, conn->list->set.major_version);
		return -1;
	}

	conn->minor_version = minor_version;
	conn->version_received = TRUE;
	return 0;
}

int connection_handshake_args_default(struct connection *conn,
				      const char *const *args)
{
	unsigned int major_version, minor_version;

	if (conn->version_received)
		return 1;

	/* VERSION <tab> service_name <tab> major version <tab> minor version */
	if (str_array_length(args) != 4 ||
	    strcmp(args[0], "VERSION") != 0 ||
	    str_to_uint(args[2], &major_version) < 0 ||
	    str_to_uint(args[3], &minor_version) < 0) {
		e_error(conn->event, "didn't reply with a valid VERSION line: %s",
			t_strarray_join(args, "\t"));
		return -1;
	}

	if (connection_verify_version(conn, args[1],
				      major_version, minor_version) < 0)
		return -1;
	return 1;
}

int connection_input_line_default(struct connection *conn, const char *line)
{
	const char *const *args;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL && !conn->list->set.allow_empty_args_input) {
		e_error(conn->event, "Unexpectedly received empty line");
		return -1;
	}

	if (!conn->handshake_received &&
	    (conn->v.handshake_args != connection_handshake_args_default ||
	     conn->list->set.major_version != 0)) {
		int ret;
		if ((ret = conn->v.handshake_args(conn, args)) == 0)
			ret = 1; /* continue reading */
		else if (ret > 0)
			connection_handshake_ready(conn);
		else {
			conn->disconnect_reason =
				CONNECTION_DISCONNECT_HANDSHAKE_FAILED;
		}
		return ret;
	} else if (!conn->handshake_received) {
		/* we don't do handshakes */
		connection_handshake_ready(conn);
	}

	/* version must be handled though, by something */
	i_assert(conn->version_received);

	return conn->v.input_args(conn, args);
}

void connection_input_halt(struct connection *conn)
{
	io_remove(&conn->io);
	timeout_remove(&conn->to);
}

void connection_input_resume(struct connection *conn)
{
	i_assert(!conn->disconnected);

	if (conn->io != NULL) {
		/* do nothing */
	} else if (conn->input != NULL) {
		conn->io = io_add_istream_to(conn->ioloop, conn->input,
					     *conn->v.input, conn);
	} else if (conn->fd_in != -1) {
		conn->io = io_add_to(conn->ioloop, conn->fd_in, IO_READ,
				     *conn->v.input, conn);
	}
	if (conn->input_idle_timeout_secs != 0 && conn->to == NULL) {
		conn->to = timeout_add_to(conn->ioloop,
					  conn->input_idle_timeout_secs*1000,
					  *conn->v.idle_timeout, conn);
	}
}

static void
connection_update_property_label(struct connection *conn)
{
	const char *label;

	if (conn->remote_ip.family == 0) {
		if (conn->remote_uid == (uid_t)-1)
			label = NULL;
		else if (conn->remote_pid != (pid_t)-1) {
			label = t_strdup_printf("pid=%ld,uid=%ld",
						(long)conn->remote_pid,
						(long)conn->remote_uid);
		} else {
			label = t_strdup_printf("uid=%ld",
						(long)conn->remote_uid);
		}
	} else if (conn->remote_ip.family == AF_INET6) {
		label = t_strdup_printf("[%s]:%u",
					net_ip2addr(&conn->remote_ip),
					conn->remote_port);
	} else {
		label = t_strdup_printf("%s:%u",
					net_ip2addr(&conn->remote_ip),
					conn->remote_port);
	}

	i_free(conn->property_label);
	conn->property_label = i_strdup(label);
}

static void
connection_update_label(struct connection *conn)
{
	bool unix_socket = conn->unix_socket ||
		(conn->remote_ip.family == 0 && conn->remote_uid != (uid_t)-1);
	string_t *label;

	label = t_str_new(64);
	if (conn->name != NULL)
		str_append(label, conn->name);
	if (conn->property_label != NULL) {
		if (str_len(label) == 0)
			str_append(label, conn->property_label);
		else {
			str_append(label, " (");
			str_append(label, conn->property_label);
			str_append(label, ")");
		}
	}
	if (str_len(label) == 0) {
		if (conn->fd_in >= 0 &&
		    (conn->fd_in == conn->fd_out || conn->fd_out < 0))
			str_printfa(label, "fd=%d", conn->fd_in);
		else if (conn->fd_in < 0 && conn->fd_out >= 0)
			str_printfa(label, "fd=%d", conn->fd_out);
		else if (conn->fd_in >= 0 && conn->fd_out >= 0) {
			str_printfa(label, "fd_in=%d,fd_out=%d",
				    conn->fd_in, conn->fd_out);
		}
	}
	if (unix_socket && str_len(label) > 0)
		str_insert(label, 0, "unix:");
	if (conn->list->set.log_connection_id) {
		if (str_len(label) > 0)
			str_append_c(label, ' ');
		str_printfa(label, "[%u]", conn->id);
	}

	i_free(conn->label);
	conn->label = i_strdup(str_c(label));
}

static void
connection_update_properties(struct connection *conn)
{
	int fd = (conn->fd_in < 0 ? conn->fd_out : conn->fd_in);
	struct net_unix_cred cred;

	if (conn->remote_ip.family != 0)
		i_assert(conn->remote_port != 0);
	else if (conn->fd_in != conn->fd_out || fd < 0 ||
		 net_getpeername(fd, &conn->remote_ip,
				 &conn->remote_port) < 0 ||
		 conn->remote_ip.family == 0) {
		conn->remote_ip.family = 0;
		conn->remote_port = 0;

		if (conn->unix_peer_known) {
			/* already known */
		} else if (fd < 0 || errno == ENOTSOCK ||
		      net_getunixcred(fd, &cred) < 0) {
			conn->remote_uid = (uid_t)-1;
			conn->remote_pid = (pid_t)-1;
		} else {
			conn->remote_pid = cred.pid;
			conn->remote_uid = cred.uid;
		}
		conn->unix_peer_known = TRUE;
	} else {
		conn->remote_uid = (uid_t)-1;
		conn->remote_pid = (pid_t)-1;
	}

	connection_update_property_label(conn);
	connection_update_label(conn);
}

static void connection_init_streams(struct connection *conn)
{
	const struct connection_settings *set = &conn->list->set;

	i_assert(conn->io == NULL);
	i_assert(conn->input == NULL);
	i_assert(conn->output == NULL);
	i_assert(conn->to == NULL);

	conn->handshake_received = FALSE;
	conn->version_received = set->major_version == 0;

	if (set->input_max_size != 0) {
		if (conn->unix_socket)
			conn->input = i_stream_create_unix(conn->fd_in,
							   set->input_max_size);
		else
			conn->input = i_stream_create_fd(conn->fd_in,
							 set->input_max_size);
		i_stream_set_name(conn->input, conn->name);
		i_stream_switch_ioloop_to(conn->input, conn->ioloop);
	}
	if (set->output_max_size != 0) {
		if (conn->unix_socket)
			conn->output = o_stream_create_unix(conn->fd_out,
							    set->output_max_size);
		else
			conn->output = o_stream_create_fd(conn->fd_out,
							  set->output_max_size);
		o_stream_set_no_error_handling(conn->output, TRUE);
		o_stream_set_finish_via_child(conn->output, FALSE);
		o_stream_set_name(conn->output, conn->name);
		o_stream_switch_ioloop_to(conn->output, conn->ioloop);
	}
	conn->disconnected = FALSE;
	i_assert(conn->to == NULL);
	connection_input_resume(conn);
	i_assert(conn->to != NULL || conn->input_idle_timeout_secs == 0);
	if (set->major_version != 0 && !set->dont_send_version) {
		e_debug(conn->event, "Sending version handshake");
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"VERSION\t%s\t%u\t%u\n", set->service_name_out,
			set->major_version, set->minor_version));
	}
}

void connection_streams_changed(struct connection *conn)
{
	const struct connection_settings *set = &conn->list->set;

	if (set->input_max_size != 0 && conn->io != NULL) {
		connection_input_halt(conn);
		connection_input_resume(conn);
	}
}

static void connection_client_connected(struct connection *conn, bool success)
{
	struct event_passthrough *e = event_create_passthrough(conn->event)->
		set_name("server_connection_connected");

	i_assert(conn->list->set.client);

	connection_update_properties(conn);

	conn->connect_finished = ioloop_timeval;
	event_add_timeval(conn->event, "connect_finished_time",
			  &ioloop_timeval);

	if (success) {
		e_debug(e->event(), "Client connected (fd=%d)",
			conn->fd_in);
	} else {
		e_debug(e->event(), "Client connection failed (fd=%d)",
			conn->fd_in);
	}

	if (success)
		connection_init_streams(conn);
	if (conn->v.client_connected != NULL)
		conn->v.client_connected(conn, success);
	if (!success) {
		connection_closed(conn, CONNECTION_DISCONNECT_CONN_CLOSED);
	}
}

static void
connection_init_full(struct connection_list *list, struct connection *conn,
		     const char *name, int fd_in, int fd_out)
{
	if (conn->id == 0) {
		if (list->id_counter == 0)
			list->id_counter++;
		conn->id = list->id_counter++;
	}

	conn->ioloop = current_ioloop;
	conn->fd_in = fd_in;
	conn->fd_out = fd_out;
	conn->disconnected = TRUE;

	i_free(conn->name);
	conn->name = i_strdup(name);

	if (list->set.input_idle_timeout_secs != 0 &&
	    conn->input_idle_timeout_secs == 0) {
		conn->input_idle_timeout_secs =
			list->set.input_idle_timeout_secs;
	}

	if (conn->event == NULL)
		conn->event = event_create(conn->event_parent);
	if (list->set.debug)
		event_set_forced_debug(conn->event, TRUE);

	if (conn->list != NULL) {
		i_assert(conn->list == list);
	} else {
		conn->list = list;
		DLLIST_PREPEND(&list->connections, conn);
		list->connections_count++;
	}

	connection_update_properties(conn);
	connection_set_default_handlers(conn);
}

void connection_init(struct connection_list *list, struct connection *conn,
		     const char *name)
{
	connection_init_full(list, conn, name, -1, -1);
}

void connection_init_server(struct connection_list *list,
			    struct connection *conn, const char *name,
			    int fd_in, int fd_out)
{
	i_assert(name != NULL);
	i_assert(!list->set.client);

	connection_init_full(list, conn, name, fd_in, fd_out);

	event_set_append_log_prefix(conn->event,
				    t_strdup_printf("(%s): ", conn->name));

	struct event_passthrough *e = event_create_passthrough(conn->event)->
		set_name("client_connection_connected");
	/* fd_out differs from fd_in only for stdin/stdout. Keep the logging
	   output nice and clean by logging only the fd_in. If it's 0, it'll
	   also be obvious that fd_out=1. */
	e_debug(e->event(), "Server accepted connection (fd=%d)", fd_in);

	connection_init_streams(conn);
}

void connection_init_server_ip(struct connection_list *list,
			       struct connection *conn, const char *name,
			       int fd_in, int fd_out,
			       const struct ip_addr *remote_ip,
			       in_port_t remote_port)
{
	if (remote_ip != NULL && remote_ip->family != 0)
		conn->remote_ip = *remote_ip;
	if (remote_port != 0)
		conn->remote_port = remote_port;

	connection_init_server(list, conn, name, fd_in, fd_out);
}

void connection_init_client_fd(struct connection_list *list,
			       struct connection *conn, const char *name,
			       int fd_in, int fd_out)
{
	i_assert(name != NULL);
	i_assert(list->set.client);

	connection_init_full(list, conn, name, fd_in, fd_out);

	event_set_append_log_prefix(conn->event,
				    t_strdup_printf("(%s): ", conn->name));

	struct event_passthrough *e = event_create_passthrough(conn->event)->
		set_name("server_connection_connected");
	/* fd_out differs from fd_in only for stdin/stdout. Keep the logging
	   output nice and clean by logging only the fd_in. If it's 0, it'll
	   also be obvious that fd_out=1. */
	e_debug(e->event(), "Client connected (fd=%d)", fd_in);

	connection_client_connected(conn, TRUE);
}

void connection_init_client_ip_from(struct connection_list *list,
				    struct connection *conn, const char *name,
				    const struct ip_addr *ip, in_port_t port,
				    const struct ip_addr *my_ip)
{
	i_assert(list->set.client);

	if (name == NULL)
		name = t_strdup_printf("%s:%u", net_ip2addr(ip), port);

	conn->remote_ip = *ip;
	conn->remote_port = port;

	if (my_ip != NULL)
		conn->local_ip = *my_ip;
	else
		i_zero(&conn->local_ip);

	connection_init(list, conn, name);

	if (my_ip != NULL)
		event_add_str(conn->event, "client_ip", net_ip2addr(my_ip));
	event_add_str(conn->event, "ip", net_ip2addr(ip));
	event_add_str(conn->event, "port", dec2str(port));
	event_set_append_log_prefix(conn->event,
				    t_strdup_printf("(%s): ", conn->name));
}

void connection_init_client_ip(struct connection_list *list,
			       struct connection *conn, const char *name,
			       const struct ip_addr *ip, in_port_t port)
{
	connection_init_client_ip_from(list, conn, name, ip, port, NULL);
}

void connection_init_client_unix(struct connection_list *list,
				 struct connection *conn, const char *path)
{
	i_assert(list->set.client);

	conn->unix_socket = TRUE;

	connection_init(list, conn, path);

	event_field_clear(conn->event, "ip");
	event_field_clear(conn->event, "port");
	event_field_clear(conn->event, "client_ip");
	event_field_clear(conn->event, "client_port");

	event_set_append_log_prefix(conn->event,
				    t_strdup_printf("(%s): ",
						    basename(conn->name)));
}

void connection_init_from_streams(struct connection_list *list,
				  struct connection *conn, const char *name,
				  struct istream *input, struct ostream *output)
{
	i_assert(name != NULL);

	connection_init_full(list, conn, name,
			     i_stream_get_fd(input), o_stream_get_fd(output));

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
	event_set_append_log_prefix(conn->event,
				    t_strdup_printf("(%s): ", conn->name));

	conn->disconnected = FALSE;
	connection_input_resume(conn);

	if (conn->v.client_connected != NULL)
		conn->v.client_connected(conn, TRUE);
}

static void connection_socket_connected(struct connection *conn)
{
	io_remove(&conn->io);
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

	e_debug(conn->event, "Connecting");

	if (conn->remote_port != 0) {
		fd = net_connect_ip(&conn->remote_ip, conn->remote_port,
				    (conn->local_ip.family != 0 ?
				     &conn->local_ip : NULL));
	} else if (conn->list->set.unix_client_connect_msecs == 0) {
		fd = net_connect_unix(conn->name);
	} else {
		fd = net_connect_unix_with_retries(
			conn->name, conn->list->set.unix_client_connect_msecs);
	}
	if (fd == -1)
		return -1;
	conn->fd_in = conn->fd_out = fd;
	conn->connect_started = ioloop_timeval;
	conn->disconnected = FALSE;

	if (conn->remote_port != 0 ||
	    conn->list->set.delayed_unix_client_connected_callback) {
		connection_update_properties(conn);
		conn->io = io_add_to(conn->ioloop, conn->fd_out, IO_WRITE,
				     connection_socket_connected, conn);
		e_debug(conn->event,
			"Waiting for connect (fd=%d) to finish for max %u msecs",
			fd, set->client_connect_timeout_msecs);
		if (set->client_connect_timeout_msecs != 0) {
			conn->to = timeout_add_to(conn->ioloop,
						  set->client_connect_timeout_msecs,
						  *conn->v.connect_timeout, conn);
		}
	} else {
		connection_client_connected(conn, TRUE);
	}
	return 0;
}

static void connection_update_counters(struct connection *conn)
{
	if (conn->input != NULL)
		event_add_int(conn->event, "bytes_in", conn->input->v_offset);
	if (conn->output != NULL)
		event_add_int(conn->event, "bytes_out", conn->output->offset);
}

void connection_disconnect(struct connection *conn)
{
	if (conn->disconnected)
		return;
	connection_update_counters(conn);
	/* client connects to a Server, and Server gets connection from Client
	 */
	const char *ename = conn->list->set.client ?
		"server_connection_disconnected" :
		"client_connection_disconnected";

	struct event_passthrough *e = event_create_passthrough(conn->event)->
		set_name(ename)->
		add_str("reason", connection_disconnect_reason(conn));
	e_debug(e->event(), "Disconnected: %s (fd=%d)",
		connection_disconnect_reason(conn), conn->fd_in);

	conn->last_input = 0;
	i_zero(&conn->last_input_tv);
	timeout_remove(&conn->to);
	io_remove(&conn->io);
	i_stream_close(conn->input);
	i_stream_destroy(&conn->input);
	o_stream_close(conn->output);
	o_stream_destroy(&conn->output);
	fd_close_maybe_stdio(&conn->fd_in, &conn->fd_out);
	conn->disconnected = TRUE;
}

void connection_deinit(struct connection *conn)
{
	i_assert(conn->list->connections_count > 0);

	conn->list->connections_count--;
	DLLIST_REMOVE(&conn->list->connections, conn);

	connection_disconnect(conn);
	i_free(conn->name);
	i_free(conn->label);
	i_free(conn->property_label);
	event_unref(&conn->event);
	conn->list = NULL;
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
			connection_closed(conn,
					  CONNECTION_DISCONNECT_BUFFER_FULL);
			return -1;
		case CONNECTION_BEHAVIOR_ALLOW:
			return -2;
		}
		i_unreached();
	case -1:
		/* disconnected */
		connection_closed(conn, CONNECTION_DISCONNECT_CONN_CLOSED);
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
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		return "Handshake failed";
	}
	i_unreached();
}

const char *connection_input_timeout_reason(struct connection *conn)
{
	if (conn->last_input_tv.tv_sec != 0) {
		int diff = timeval_diff_msecs(&ioloop_timeval,
					      &conn->last_input_tv);
		return t_strdup_printf("No input for %u.%03u secs",
				       diff/1000, diff%1000);
	} else if (conn->connect_finished.tv_sec != 0) {
		int diff = timeval_diff_msecs(&ioloop_timeval,
					      &conn->connect_finished);
		return t_strdup_printf(
			"No input since connected %u.%03u secs ago",
			diff/1000, diff%1000);
	} else {
		int diff = timeval_diff_msecs(&ioloop_timeval,
					      &conn->connect_started);
		return t_strdup_printf("connect() timed out after %u.%03u secs",
				       diff/1000, diff%1000);
	}
}

void connection_set_handlers(struct connection *conn,
			     const struct connection_vfuncs *vfuncs)
{
	connection_input_halt(conn);
	i_assert(vfuncs->destroy != NULL);
	conn->v = *vfuncs;
        if (conn->v.input == NULL)
                conn->v.input = connection_input_default;
        if (conn->v.input_line == NULL)
                conn->v.input_line = connection_input_line_default;
        if (conn->v.handshake_args == NULL)
                conn->v.handshake_args = connection_handshake_args_default;
        if (conn->v.idle_timeout == NULL)
                conn->v.idle_timeout = connection_idle_timeout;
        if (conn->v.connect_timeout == NULL)
                conn->v.connect_timeout = connection_connect_timeout;
	if (!conn->disconnected)
		connection_input_resume(conn);
}

void connection_set_default_handlers(struct connection *conn)
{
	connection_set_handlers(conn, &conn->list->v);
}

void connection_switch_ioloop_to(struct connection *conn,
				 struct ioloop *ioloop)
{
	conn->ioloop = ioloop;
	if (conn->io != NULL)
		conn->io = io_loop_move_io_to(ioloop, &conn->io);
	if (conn->to != NULL)
		conn->to = io_loop_move_timeout_to(ioloop, &conn->to);
	if (conn->input != NULL)
		i_stream_switch_ioloop_to(conn->input, ioloop);
	if (conn->output != NULL)
		o_stream_switch_ioloop_to(conn->output, ioloop);
}

void connection_switch_ioloop(struct connection *conn)
{
	connection_switch_ioloop_to(conn, current_ioloop);
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
		  set->service_name_out != NULL &&
		  set->output_max_size != 0));

	list = i_new(struct connection_list, 1);
	list->set = *set;
	list->v = *vfuncs;

	return list;
}

void connection_list_deinit(struct connection_list **_list)
{
	struct connection_list *list = *_list;
	struct connection *conn;

	*_list = NULL;

	while (list->connections != NULL) {
		conn = list->connections;
		connection_closed(conn, CONNECTION_DISCONNECT_DEINIT);
		i_assert(conn != list->connections);
	}
	i_free(list);
}
