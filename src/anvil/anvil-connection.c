/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "istream-multiplex.h"
#include "ostream-multiplex.h"
#include "connection.h"
#include "strescape.h"
#include "master-service.h"
#include "master-interface.h"
#include "connect-limit.h"
#include "penalty.h"
#include "anvil-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE 1024

#define ANVIL_CLIENT_PROTOCOL_MAJOR_VERSION 2
#define ANVIL_CLIENT_PROTOCOL_MINOR_VERSION 0

struct anvil_connection {
	struct connection conn;

	char *service;
	bool master:1;
	bool fifo:1;
};

static struct connection_list *anvil_connections;

static void anvil_connection_destroy(struct connection *_conn);

static bool
connect_limit_key_parse(const char *const **_args,
			struct connect_limit_key *key_r)
{
	const char *const *args = *_args;

	/* <username> <service> <ip> */
	if (str_array_length(args) < 3)
		return FALSE;

	i_zero(key_r);
	key_r->username = args[0];
	key_r->service = args[1];
	if (args[2][0] != '\0' && net_addr2ip(args[2], &key_r->ip) < 0)
		return FALSE;

	*_args += 3;
	return TRUE;
}

static int str_to_kick_type(const char *str, enum kick_type *kick_type_r)
{
	switch (str[0]) {
	case 'N':
		*kick_type_r = KICK_TYPE_NONE;
		break;
	case 'S':
		*kick_type_r = KICK_TYPE_SIGNAL;
		break;
	case 'A':
		*kick_type_r = KICK_TYPE_ADMIN_SOCKET;
		break;
	default:
		return -1;
	}
	return str[1] == '\0' ? 0 : -1;
}

static int
anvil_connection_request(struct anvil_connection *conn,
			 const char *const *args, const char **error_r)
{
	const char *cmd = args[0];
	guid_128_t conn_guid;
	struct connect_limit_key key;
	unsigned int value, checksum;
	time_t stamp;
	pid_t pid;

	args++;
	if (strcmp(cmd, "CONNECT") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "CONNECT: Not enough parameters";
			return -1;
		}
		if (guid_128_from_string(args[0], conn_guid) < 0) {
			*error_r = "CONNECT: Invalid conn-guid";
			return -1;
		}
		args++;
		if (str_to_pid(args[0], &pid) < 0) {
			*error_r = "CONNECT: Invalid pid";
			return -1;
		}
		args++;
		if (!connect_limit_key_parse(&args, &key)) {
			*error_r = "CONNECT: Invalid ident string";
			return -1;
		}
		/* extra parameters: */
		enum kick_type kick_type = KICK_TYPE_NONE;
		if (args[0] != NULL) {
			if (str_to_kick_type(args[0], &kick_type) < 0) {
				*error_r = "CONNECT: Invalid kick_type";
				return -1;
			}
			args++;
		}
		struct ip_addr dest_ip;
		i_zero(&dest_ip);
		if (args[0] != NULL) {
			if (args[0][0] != '\0' &&
			    net_addr2ip(args[0], &dest_ip) < 0) {
				*error_r = "CONNECT: Invalid dest_ip";
				return -1;
			}
			args++;
		}
		const char *const *alt_usernames = NULL;
		if (args[0] != NULL) {
			alt_usernames = t_strsplit_tabescaped(args[0]);
			args++;
		}
		connect_limit_connect(connect_limit, pid, &key,
				      conn_guid, kick_type, &dest_ip,
				      alt_usernames);
	} else if (strcmp(cmd, "DISCONNECT") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "DISCONNECT: Not enough parameters";
			return -1;
		}
		if (guid_128_from_string(args[0], conn_guid) < 0) {
			*error_r = "DISCONNECT: Invalid conn-guid";
			return -1;
		}
		args++;
		if (str_to_pid(args[0], &pid) < 0) {
			*error_r = "DISCONNECT: Invalid pid";
			return -1;
		}
		args++;
		if (!connect_limit_key_parse(&args, &key)) {
			*error_r = "DISCONNECT: Invalid ident string";
			return -1;
		}
		connect_limit_disconnect(connect_limit, pid, &key, conn_guid);
	} else if (strcmp(cmd, "CONNECT-DUMP") == 0) {
		connect_limit_dump(connect_limit, conn->conn.output);
	} else if (strcmp(cmd, "KILL") == 0) {
		if (args[0] == NULL) {
			*error_r = "KILL: Not enough parameters";
			return -1;
		}
		if (!conn->master) {
			*error_r = "KILL sent by a non-master connection";
			return -1;
		}
		if (str_to_pid(args[0], &pid) < 0) {
			*error_r = "KILL: Invalid pid";
			return -1;
		}
		connect_limit_disconnect_pid(connect_limit, pid);
	} else if (strcmp(cmd, "LOOKUP") == 0) {
		if (args[0] == NULL) {
			*error_r = "LOOKUP: Not enough parameters";
			return -1;
		}
		if (!connect_limit_key_parse(&args, &key)) {
			*error_r = "LOOKUP: Invalid ident string";
			return -1;
		}
		if (conn->conn.output == NULL) {
			*error_r = "LOOKUP on a FIFO, can't send reply";
			return -1;
		}
		value = connect_limit_lookup(connect_limit, &key);
		o_stream_nsend_str(conn->conn.output,
				   t_strdup_printf("%u\n", value));
	} else if (strcmp(cmd, "PENALTY-GET") == 0) {
		if (args[0] == NULL) {
			*error_r = "PENALTY-GET: Not enough parameters";
			return -1;
		}
		value = penalty_get(penalty, args[0], &stamp);
		o_stream_nsend_str(conn->conn.output,
			t_strdup_printf("%u %s\n", value, dec2str(stamp)));
	} else if (strcmp(cmd, "PENALTY-INC") == 0) {
		if (args[0] == NULL || args[1] == NULL || args[2] == NULL) {
			*error_r = "PENALTY-INC: Not enough parameters";
			return -1;
		}
		if (str_to_uint(args[1], &checksum) < 0 ||
		    str_to_uint(args[2], &value) < 0 ||
		    value > PENALTY_MAX_VALUE ||
		    (value == 0 && checksum != 0)) {
			*error_r = "PENALTY-INC: Invalid parameters";
			return -1;
		}
		penalty_inc(penalty, args[0], checksum, value);
	} else if (strcmp(cmd, "PENALTY-SET-EXPIRE-SECS") == 0) {
		if (args[0] == NULL || str_to_uint(args[0], &value) < 0) {
			*error_r = "PENALTY-SET-EXPIRE-SECS: "
				"Invalid parameters";
			return -1;
		}
		penalty_set_expire_secs(penalty, value);
	} else if (strcmp(cmd, "PENALTY-DUMP") == 0) {
		penalty_dump(penalty, conn->conn.output);
	} else {
		*error_r = t_strconcat("Unknown command: ", cmd, NULL);
		return -1;
	}
	return 0;
}

static int
anvil_connection_handshake(struct anvil_connection *conn,
			   const char *const *args)
{
	/* UNIX socket connections contain a handshake. It contains a PID of
	   the connecting process, which is verified with UNIX credentials if
	   they're available. */
	pid_t pid;

	if (args[0] == NULL) {
		/* No service/pid. The client doesn't support admin-commands
		   via anvil socket. */
		return 0;
	}

	conn->service = i_strdup(args[0]);
	if (args[1] == NULL || str_to_pid(args[1], &pid) < 0) {
		e_error(conn->conn.event, "Invalid handshake pid: %s", args[1]);
		return -1;
	}
	if (pid != conn->conn.remote_pid &&
	    conn->conn.remote_pid != (pid_t)-1) {
		e_error(conn->conn.event,
			"Handshake PID %ld doesn't match UNIX credentials PID %ld",
			(long)pid, (long)conn->conn.remote_pid);
		return -1;
	}

	/* Switch input and output to use multiplex stream. The main
	   input/output contains the first channel. */
	struct istream *orig_input = conn->conn.input;
	conn->conn.input = i_stream_create_multiplex(orig_input, MAX_INBUF_SIZE);
	i_stream_unref(&orig_input);

	struct ostream *orig_output = conn->conn.output;
	conn->conn.output = o_stream_create_multiplex(orig_output, SIZE_MAX);
	o_stream_set_no_error_handling(conn->conn.output, TRUE);
	o_stream_unref(&orig_output);

	connection_streams_changed(&conn->conn);
	return 0;
}

static int
anvil_connection_input_line(struct connection *_conn, const char *line)
{
	struct anvil_connection *conn =
		container_of(_conn, struct anvil_connection, conn);
	const char *const *args, *error;

	if (!conn->conn.version_received) {
		if (!version_string_verify(line, "anvil-client",
				ANVIL_CLIENT_PROTOCOL_MAJOR_VERSION)) {
			if (anvil_restarted && (conn->master || conn->fifo)) {
				/* old pending data. ignore input until we get
				   the handshake. */
				return 1;
			}
			i_error("Anvil client not compatible with this server "
				"(mixed old and new binaries?) %s", line);
			return -1;
		}
		conn->conn.version_received = TRUE;
		return 1;
	}

	args = t_strsplit_tabescaped(line);
	if (!conn->conn.handshake_received && !conn->fifo) {
		if (anvil_connection_handshake(conn, args) < 0)
			return -1;
		conn->conn.handshake_received = TRUE;
		return 1;
	}

	if (args[0] == NULL) {
		i_error("Anvil client sent empty line");
		return -1;
	}

	if (anvil_connection_request(conn, args, &error) < 0) {
		i_error("Anvil client input error: %s: %s", error, line);
		return -1;
	}
	return 1;
}

void anvil_connection_create(int fd, bool master, bool fifo)
{
	struct anvil_connection *conn;

	conn = i_new(struct anvil_connection, 1);
	connection_init_server(anvil_connections, &conn->conn, "anvil", fd, fd);
	conn->conn.version_received = FALSE;
	if (!fifo) {
		conn->conn.output = o_stream_create_fd(fd, SIZE_MAX);
		o_stream_set_no_error_handling(conn->conn.output, TRUE);
		o_stream_nsend_str(conn->conn.output,
				   "VERSION\tanvil-server\t2\t0\n");
	}
	conn->master = master;
	conn->fifo = fifo;
}

static void anvil_connection_destroy(struct connection *_conn)
{
	struct anvil_connection *conn =
		container_of(_conn, struct anvil_connection, conn);
	bool fifo = conn->fifo;

	connection_deinit(&conn->conn);
	o_stream_destroy(&conn->conn.output);
	i_free(conn->service);
	i_free(conn);

	if (!fifo)
		master_service_client_connection_destroyed(master_service);
}

static struct connection_settings anvil_connections_set = {
	.dont_send_version = TRUE,
	.input_max_size = MAX_INBUF_SIZE,
};

static struct connection_vfuncs anvil_connections_vfuncs = {
	.destroy = anvil_connection_destroy,
	.input_line = anvil_connection_input_line,
};

void anvil_connections_init(void)
{
	anvil_connections = connection_list_init(&anvil_connections_set,
						 &anvil_connections_vfuncs);
}

void anvil_connections_deinit(void)
{
	connection_list_deinit(&anvil_connections);
}
