/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "istream-multiplex.h"
#include "ostream-multiplex.h"
#include "connection.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "master-interface.h"
#include "connect-limit.h"
#include "penalty.h"
#include "admin-client.h"
#include "anvil-connection.h"

#include <unistd.h>
#include <signal.h>

#define MAX_INBUF_SIZE 1024

#define ANVIL_CLIENT_PROTOCOL_MAJOR_VERSION 2
#define ANVIL_CLIENT_PROTOCOL_MINOR_VERSION 0

#define ANVIL_CMD_CHANNEL_ID 1

struct anvil_connection_key {
	const char *service;
	pid_t pid;
};

struct anvil_connection_command {
	char *cmdline;
	anvil_connection_cmd_callback_t *callback;
	void *context;
};

struct anvil_connection {
	struct connection conn;
	int refcount;

	ARRAY(struct anvil_connection_command) commands;

	struct istream *cmd_input;
	struct ostream *cmd_output;
	struct io *cmd_io;

	char *service;
	bool master:1;
	bool fifo:1;
	bool added_to_hash:1;
};

struct anvil_cmd_kick_target {
	struct anvil_cmd_kick *kick;

	char *username;
	char *service;
	pid_t pid;
	enum kick_type kick_type;

	struct admin_client *client;
};

struct anvil_cmd_kick {
	struct anvil_cmd_kick *prev, *next;
	struct anvil_connection *conn;
	struct connect_limit_iter *iter;
	bool add_conn_guid;

	pid_t prev_pid;
	int cmd_refcount;
	unsigned int kick_count;
};

static struct connection_list *anvil_connections;
static HASH_TABLE(struct anvil_connection_key *, struct anvil_connection *)
	anvil_connections_hash;
static unsigned int anvil_global_kick_count = 0;
static unsigned int anvil_global_cmd_counter = 0;
static unsigned int anvil_global_connect_dump_count = 0;
static char *anvil_base_dir;
static struct anvil_cmd_kick *anvil_kicks;
static struct timeout *to_kick;
static unsigned int anvil_max_kick_connections;

static void anvil_connection_destroy(struct connection *_conn);
static bool kick_user_iter_more(struct anvil_cmd_kick *kick);

static void anvil_connection_unref(struct anvil_connection **_conn)
{
	struct anvil_connection *conn = *_conn;

	*_conn = NULL;
	i_assert(conn->refcount > 0);
	if (--conn->refcount == 0)
		i_free(conn);
}

static unsigned int
anvil_connection_key_hash(const struct anvil_connection_key *key)
{
	return str_hash(key->service) ^ key->pid;
}

static int anvil_connection_key_cmp(const struct anvil_connection_key *key1,
				    const struct anvil_connection_key *key2)
{
	if (key1->pid != key2->pid)
		return 1;
	return strcmp(key1->service, key2->service);
}

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
	case 'W':
		*kick_type_r = KICK_TYPE_SIGNAL_WITH_SOCKET;
		break;
	default:
		return -1;
	}
	return str[1] == '\0' ? 0 : -1;
}

static void
anvil_connection_cmd_reply(struct anvil_connection *conn,
			   const char *reply, const char *error)
{
	struct anvil_connection_command *cmd;

	cmd = array_idx_modifiable(&conn->commands, 0);
	cmd->callback(reply, error, cmd->context);
	i_free(cmd->cmdline);
	array_pop_front(&conn->commands);
}

static void anvil_cmd_input(struct anvil_connection *conn)
{
	const char *line;

	if (connection_input_read_stream(&conn->conn, conn->cmd_input) < 0)
		return;

	while ((line = i_stream_next_line(conn->cmd_input)) != NULL) {
		if (array_count(&conn->commands) == 0) {
			e_error(conn->conn.event,
				"Unexpected input from command channel: %s",
				line);
		} else {
			anvil_connection_cmd_reply(conn, line, NULL);
		}
	}
}

static void kick_user_finished(struct anvil_cmd_kick *kick)
{
	i_assert(kick->cmd_refcount == 0);
	i_assert(kick->iter == NULL);

	if (kick->conn->conn.output != NULL) {
		o_stream_nsend_str(kick->conn->conn.output,
				   t_strdup_printf("%u\n", kick->kick_count));
	}
	anvil_connection_unref(&kick->conn);
	DLLIST_REMOVE(&anvil_kicks, kick);
	i_free(kick);
}

static void kick_more(void *context ATTR_UNUSED)
{
	struct anvil_cmd_kick *kick, *next;

	timeout_remove(&to_kick);
	for (kick = anvil_kicks; kick != NULL; kick = next) {
		next = kick->next;
		if (!kick_user_iter_more(kick))
			break;
	}
}

static void
kick_user_callback(const char *reply, const char *error,
		   struct anvil_cmd_kick_target *target)
{
	struct anvil_cmd_kick *kick = target->kick;
	unsigned int count;

	i_assert(kick->cmd_refcount > 0);
	i_assert(anvil_global_kick_count > 0);

	anvil_global_kick_count--;
	anvil_refresh_proctitle_delayed();
	if (error != NULL)
		;
	else if (reply[0] == '+' && str_to_uint(reply+1, &count) == 0)
		kick->kick_count += count;
	else {
		e_error(kick->conn->conn.event,
			"Invalid %s %s reply sent to service %s PID %ld: %s",
			target->kick_type == KICK_TYPE_SIGNAL_WITH_SOCKET ?
			"KICK-USER-SIGNAL" : "KICK-USER",
			target->username, target->service,
			(long)target->pid, reply);
	}

	admin_client_unref(&target->client);
	kick->cmd_refcount--;
	if (kick->iter != NULL) {
		if (to_kick == NULL)
			to_kick = timeout_add_short(0, kick_more, NULL);
	} else if (kick->cmd_refcount == 0) {
		kick_user_finished(kick);
	}
	i_free(target->username);
	i_free(target->service);
	i_free(target);
}

static void
kick_user_with_signal(struct anvil_cmd_kick_target *target, const char *cmd)
{
	/* Always create a new admin-client connection to the destination
	   process, even if one already existed. This way the process's signal
	   handler can accept() the connection and handle the kick command
	   immediately. */
	target->client =
		admin_client_init(anvil_base_dir, target->service, target->pid);
	admin_client_send_cmd(target->client, cmd, kick_user_callback, target);
	if (kill(target->pid, SIGTERM) == 0)
		target->kick->kick_count++;
	else if (errno != ESRCH) {
		e_error(target->kick->conn->conn.event, "kill(%ld) failed: %m",
			(long)target->pid);
	}
}

static bool kick_user_iter_more(struct anvil_cmd_kick *kick)
{
	struct connect_limit_iter_result result;
	string_t *cmd = t_str_new(128);

	for (;;) {
		if (anvil_global_kick_count >= anvil_max_kick_connections) {
			/* Continue after some of the kicks have finished */
			return FALSE;
		}
		if (!connect_limit_iter_next(kick->iter, &result))
			break;

		switch (result.kick_type) {
		case KICK_TYPE_NONE:
			break;
		case KICK_TYPE_SIGNAL:
			if (kick->prev_pid == result.pid) {
				/* Already killed this pid. Note that the
				   results are sorted by pid and kick_type
				   is the same for all sessions within the
				   process. */
				break;
			}
			if (kill(result.pid, SIGTERM) == 0)
				kick->kick_count++;
			else if (errno != ESRCH) {
				e_error(kick->conn->conn.event,
					"kill(%ld) failed: %m",
					(long)result.pid);
			}
			break;
		case KICK_TYPE_ADMIN_SOCKET:
		case KICK_TYPE_SIGNAL_WITH_SOCKET:
			str_truncate(cmd, 0);
			if (result.kick_type == KICK_TYPE_SIGNAL_WITH_SOCKET)
				str_append(cmd, "KICK-USER-SIGNAL\t");
			else
				str_append(cmd, "KICK-USER\t");
			str_append_tabescaped(cmd, result.username);
			if (!guid_128_is_empty(result.conn_guid) &&
			    kick->add_conn_guid) {
				str_append_c(cmd, '\t');
				str_append_tabescaped(cmd,
					guid_128_to_string(result.conn_guid));
			}

			struct anvil_cmd_kick_target *target =
				i_new(struct anvil_cmd_kick_target, 1);
			target->kick = kick;
			target->username = i_strdup(result.username);
			target->service = i_strdup(result.service);
			target->pid = result.pid;
			target->kick_type = result.kick_type;

			anvil_global_kick_count++;
			kick->cmd_refcount++;
			if (result.kick_type == KICK_TYPE_SIGNAL_WITH_SOCKET)
				kick_user_with_signal(target, str_c(cmd));
			else {
				admin_cmd_send(result.service, result.pid,
					       str_c(cmd),
					       kick_user_callback, target);
			}
			break;
		}
		kick->prev_pid = result.pid;
	}
	connect_limit_iter_deinit(&kick->iter);
	if (kick->cmd_refcount == 0)
		kick_user_finished(kick);
	return TRUE;
}

static void
kick_user_iter(struct anvil_connection *conn, struct connect_limit_iter *iter,
	       bool add_conn_guid)
{
	struct anvil_cmd_kick *kick;

	kick = i_new(struct anvil_cmd_kick, 1);
	kick->conn = conn;
	kick->iter = iter;
	kick->add_conn_guid = add_conn_guid;
	kick->prev_pid = (pid_t)-1;
	conn->refcount++;
	DLLIST_PREPEND(&anvil_kicks, kick);

	(void)kick_user_iter_more(kick);
}

static void kick_user(struct anvil_connection *conn, const char *username,
		      const guid_128_t conn_guid)
{
	struct connect_limit_iter *iter;

	iter = connect_limit_iter_begin(connect_limit, username, conn_guid);
	kick_user_iter(conn, iter, FALSE);
}

static void
kick_alt_user(struct anvil_connection *conn,
	      const char *alt_username_field, const char *alt_username,
	      const struct ip_addr *except_ip)
{
	struct connect_limit_iter *iter;

	iter = connect_limit_iter_begin_alt_username(connect_limit,
			alt_username_field, alt_username, except_ip);
	kick_user_iter(conn, iter, TRUE);
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

	anvil_global_cmd_counter++;
	anvil_refresh_proctitle_delayed();

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
		anvil_global_connect_dump_count++;
		connect_limit_dump(connect_limit, conn->conn.output);
	} else if (strcmp(cmd, "KICK-USER") == 0) {
		if (args[0] == NULL) {
			*error_r = "KICK-USER: Not enough parameters";
			return -1;
		}
		guid_128_t conn_guid;
		if (args[1] == NULL)
			guid_128_empty(conn_guid);
		else if (guid_128_from_string(args[1], conn_guid) < 0) {
			*error_r = "KICK-USER: Invalid conn-guid";
			return -1;
		}
		kick_user(conn, args[0], conn_guid);
	} else if (strcmp(cmd, "KICK-ALT-USER") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "KICK-ALT-USER: Not enough parameters";
			return -1;
		}
		struct ip_addr except_ip;
		if (args[2] == NULL)
			i_zero(&except_ip);
		else if (net_addr2ip(args[2], &except_ip) < 0) {
			*error_r = "KICK-ALT-USER: Invalid except_ip parameter";
			return -1;
		}
		kick_alt_user(conn, args[0], args[1],
			      except_ip.family == 0 ? NULL : &except_ip);
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

	/* add a separate channel for handling admin commands */
	conn->cmd_input = i_stream_multiplex_add_channel(conn->conn.input,
							 ANVIL_CMD_CHANNEL_ID);
	conn->cmd_io = io_add_istream(conn->cmd_input, anvil_cmd_input, conn);
	conn->cmd_output = o_stream_multiplex_add_channel(conn->conn.output,
							  ANVIL_CMD_CHANNEL_ID);

	struct anvil_connection_key *hash_key, key = {
		.service = conn->service,
		.pid = conn->conn.remote_pid,
	};
	struct anvil_connection *hash_conn;
	if (hash_table_lookup_full(anvil_connections_hash, &key,
				   &hash_key, &hash_conn)) {
		e_warning(conn->conn.event,
			  "Handshake with duplicate service=%s pid=%ld - "
			  "replacing the old connection",
			  key.service, (long)key.pid);
		hash_table_remove(anvil_connections_hash, hash_key);
		i_assert(hash_conn->added_to_hash);
		hash_conn->added_to_hash = FALSE;
	} else {
		hash_key = i_new(struct anvil_connection_key, 1);
		*hash_key = key;
	}
	hash_table_insert(anvil_connections_hash, hash_key, conn);
	conn->added_to_hash = TRUE;
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
			e_error(_conn->event,
				"Anvil client not compatible with this server "
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
		e_error(_conn->event, "Anvil client sent empty line");
		return -1;
	}

	if (anvil_connection_request(conn, args, &error) < 0) {
		e_error(_conn->event, "Anvil client input error: %s: %s",
			error, line);
		return -1;
	}
	return 1;
}

void anvil_connection_create(int fd, bool master, bool fifo)
{
	struct anvil_connection *conn;

	conn = i_new(struct anvil_connection, 1);
	connection_init_server(anvil_connections, &conn->conn, "anvil", fd, fd);
	conn->refcount = 1;
	conn->conn.version_received = FALSE;
	if (!fifo) {
		conn->conn.output = o_stream_create_fd(fd, SIZE_MAX);
		o_stream_set_no_error_handling(conn->conn.output, TRUE);
		o_stream_nsend_str(conn->conn.output,
				   "VERSION\tanvil-server\t2\t0\n");
	}
	conn->master = master;
	conn->fifo = fifo;
	i_array_init(&conn->commands, 8);
}

static void anvil_connection_destroy(struct connection *_conn)
{
	struct anvil_connection *conn =
		container_of(_conn, struct anvil_connection, conn);
	bool fifo = conn->fifo;

	while (array_count(&conn->commands) > 0) {
		anvil_connection_cmd_reply(conn, NULL,
			connection_disconnect_reason(_conn));
	}
	array_free(&conn->commands);
	connection_deinit(&conn->conn);

	if (conn->added_to_hash) {
		struct anvil_connection_key *hash_key, key = {
			.service = conn->service,
			.pid = conn->conn.remote_pid,
		};
		struct anvil_connection *hash_conn;
		if (!hash_table_lookup_full(anvil_connections_hash, &key,
					    &hash_key, &hash_conn))
			i_unreached();
		i_assert(hash_conn == conn);
		hash_table_remove(anvil_connections_hash, &key);
		i_free(hash_key);
	}

	o_stream_destroy(&conn->conn.output);
	io_remove(&conn->cmd_io);
	i_stream_destroy(&conn->cmd_input);
	o_stream_destroy(&conn->cmd_output);
	i_free(conn->service);
	anvil_connection_unref(&conn);

	if (!fifo)
		master_service_client_connection_destroyed(master_service);
}

struct anvil_connection *anvil_connection_find(const char *service, pid_t pid)
{
	struct anvil_connection_key key = {
		.service = service,
		.pid = pid,
	};
	return hash_table_lookup(anvil_connections_hash, &key);
}

void anvil_connection_send_cmd(struct anvil_connection *conn,
			       const char *cmdline,
			       anvil_connection_cmd_callback_t *callback,
			       void *context)
{
	struct anvil_connection_command *cmd;

	const struct const_iovec iov[] = {
		{ cmdline, strlen(cmdline) },
		{ "\n", 1 }
	};
	o_stream_nsendv(conn->cmd_output, iov, N_ELEMENTS(iov));

	cmd = array_append_space(&conn->commands);
	cmd->cmdline = i_strdup(cmdline);
	cmd->callback = callback;
	cmd->context = context;
}

void anvil_get_global_counts(unsigned int *connection_count_r,
			     unsigned int *kicks_pending_count_r,
			     unsigned int *cmd_counter_r,
			     unsigned int *connect_dump_counter_r)
{
	*connection_count_r = anvil_connections->connections_count;
	*kicks_pending_count_r = anvil_global_kick_count;
	*cmd_counter_r = anvil_global_cmd_counter;
	*connect_dump_counter_r = anvil_global_connect_dump_count;
}

static struct connection_settings anvil_connections_set = {
	.dont_send_version = TRUE,
	.input_max_size = MAX_INBUF_SIZE,
};

static struct connection_vfuncs anvil_connections_vfuncs = {
	.destroy = anvil_connection_destroy,
	.input_line = anvil_connection_input_line,
};

void anvil_connections_init(const char *base_dir,
			    unsigned int max_kick_connections)
{
	anvil_base_dir = i_strdup(base_dir);
	anvil_max_kick_connections = max_kick_connections;

	hash_table_create(&anvil_connections_hash, default_pool, 0,
			  anvil_connection_key_hash, anvil_connection_key_cmp);
	anvil_connections = connection_list_init(&anvil_connections_set,
						 &anvil_connections_vfuncs);
}

void anvil_connections_deinit(void)
{
	connection_list_deinit(&anvil_connections);

	i_assert(hash_table_count(anvil_connections_hash) == 0);
	hash_table_destroy(&anvil_connections_hash);
	timeout_remove(&to_kick);
	i_free(anvil_base_dir);
}
