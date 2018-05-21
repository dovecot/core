/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "connection.h"
#include "istream.h"
#include "istream-unix.h"
#include "ostream.h"
#include "buffer.h"
#include "base64.h"
#include "strescape.h"
#include "master-service.h"
#include "imap-client.h"
#include "imap-hibernate-client.h"

struct imap_hibernate_client {
	struct connection conn;
	struct imap_client *imap_client;
	bool imap_client_created;
	bool finished;
	bool debug;
};

struct imap_hibernate_input {
	/* input we've already read from the IMAP client. */
	buffer_t *client_input;
	/* IMAP connection state */
	buffer_t *state;
};

static struct connection_list *hibernate_clients = NULL;

static void imap_hibernate_client_destroy(struct connection *conn)
{
	struct imap_hibernate_client *client = (struct imap_hibernate_client *)conn;

	if (!client->imap_client_created)
		master_service_client_connection_destroyed(master_service);
	else if (client->finished)
		imap_client_create_finish(client->imap_client);
	connection_deinit(conn);
	i_free(conn);
}

static int
imap_hibernate_client_parse_input(const char *const *args, pool_t pool,
				  struct imap_client_state *state_r,
				  const char **error_r)
{
	const char *key, *value;
	unsigned int peer_dev_major = 0, peer_dev_minor = 0;

	i_zero(state_r);
	if (args[0] == NULL) {
		*error_r = "Missing username in input";
		return -1;
	}
	state_r->username = args[0]; args++;
	if (args[0] == NULL) {
		*error_r = "Missing mail_log_prefix in input";
		return -1;
	}
	state_r->mail_log_prefix = args[0]; args++;

	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value != NULL)
			key = t_strdup_until(*args, value++);
		else {
			key = *args;
			value = "";
		}
		if (strcmp(key, "lip") == 0) {
			if (net_addr2ip(value, &state_r->local_ip) < 0) {
				*error_r = t_strdup_printf(
					"Invalid lip value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "rip") == 0) {
			if (net_addr2ip(value, &state_r->remote_ip) < 0) {
				*error_r = t_strdup_printf(
					"Invalid rip value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "peer_dev_major") == 0) {
			if (str_to_uint(value, &peer_dev_major) < 0) {
				*error_r = t_strdup_printf(
					"Invalid peer_dev_major value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "peer_dev_minor") == 0) {
			if (str_to_uint(value, &peer_dev_minor) < 0) {
				*error_r = t_strdup_printf(
					"Invalid peer_dev_minor value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "peer_ino") == 0) {
			if (str_to_ino(value, &state_r->peer_ino) < 0) {
				*error_r = t_strdup_printf(
					"Invalid peer_ino value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "uid") == 0) {
			if (str_to_uid(value, &state_r->uid) < 0) {
				*error_r = t_strdup_printf(
					"Invalid uid value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "gid") == 0) {
			if (str_to_gid(value, &state_r->gid) < 0) {
				*error_r = t_strdup_printf(
					"Invalid gid value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "stats") == 0) {
			state_r->stats = value;
		} else if (strcmp(key, "idle-cmd") == 0) {
			state_r->idle_cmd = TRUE;
		} else if (strcmp(key, "session") == 0) {
			state_r->session_id = value;
		} else if (strcmp(key, "session_created") == 0) {
			if (str_to_time(value, &state_r->session_created) < 0) {
				*error_r = t_strdup_printf(
					"Invalid session_created value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "userdb_fields") == 0) {
			state_r->userdb_fields = value;
		} else if (strcmp(key, "notify_fd") == 0) {
			state_r->have_notify_fd = TRUE;
		} else if (strcmp(key, "idle_notify_interval") == 0) {
			if (str_to_uint(value, &state_r->imap_idle_notify_interval) < 0) {
				*error_r = t_strdup_printf(
					"Invalid idle_notify_interval value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "tag") == 0) {
			state_r->tag = i_strdup(value);
		} else if (strcmp(key, "state") == 0) {
			buffer_t *state_buf;

			state_buf = buffer_create_dynamic(pool, 1024);
			if (base64_decode(value, strlen(value), NULL,
					  state_buf) < 0) {
				*error_r = t_strdup_printf(
					"Invalid state base64 value: %s", value);
				return -1;
			}
			state_r->state = state_buf->data;
			state_r->state_size = state_buf->used;
		}
	}
	if (state_r->tag == NULL) {
		*error_r = "Missing tag";
		return -1;
	}
	if (peer_dev_major != 0 || peer_dev_minor != 0)
		state_r->peer_dev = makedev(peer_dev_major, peer_dev_minor);
	return 0;
}

static int
imap_hibernate_client_input_args(struct connection *conn,
				 const char *const *args, int fd, pool_t pool)
{
	struct imap_hibernate_client *client =
		(struct imap_hibernate_client *)conn;
	struct imap_client_state state;
	const char *error;

	if (imap_hibernate_client_parse_input(args, pool, &state, &error) < 0) {
		i_error("Failed to parse client input: %s", error);
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"-Failed to parse client input: %s\n", error));
		return -1;
	}
	client->imap_client = imap_client_create(fd, &state);
	/* the transferred imap client fd is now counted as the client. */
	client->imap_client_created = TRUE;
	return state.have_notify_fd ? 0 : 1;
}

static int
imap_hibernate_client_input_line(struct connection *conn, const char *line)
{
	struct imap_hibernate_client *client =
		(struct imap_hibernate_client *)conn;
	int fd = -1, ret;

	if (!conn->version_received) {
		if (connection_verify_version(conn, t_strsplit_tabescaped(line)) < 0)
			return -1;
		conn->version_received = TRUE;
		return 1;
	}
	if (client->finished) {
		i_error("Received unexpected line: %s", line);
		return -1;
	}

	if (client->imap_client == NULL) {
		char *const *args;
		pool_t pool;

		fd = i_stream_unix_get_read_fd(conn->input);
		if (fd == -1) {
			i_error("IMAP client fd not received");
			return -1;
		}

		pool = pool_alloconly_create("client cmd", 1024);
		args = p_strsplit_tabescaped(pool, line);
		ret = imap_hibernate_client_input_args(conn, (void *)args, fd, pool);
		if (ret >= 0 && client->debug)
			i_debug("Create client with input: %s", line);
		pool_unref(&pool);
	} else {
		fd = i_stream_unix_get_read_fd(conn->input);
		if (fd == -1) {
			i_error("IMAP notify fd not received (input: %s)", line);
			ret = -1;
		} else if (line[0] != '\0') {
			i_error("Expected empty notify fd line from client, but got: %s", line);
			o_stream_nsend_str(conn->output,
					   "Expected empty notify fd line");
			ret = -1;
		} else {
			imap_client_add_notify_fd(client->imap_client, fd);
			ret = 1;
		}
	}

	if (ret < 0) {
		if (client->imap_client != NULL)
			imap_client_destroy(&client->imap_client, NULL);
		i_close_fd(&fd);
		return -1;
	} else if (ret == 0) {
		/* still need to read another fd */
		i_stream_unix_set_read_fd(conn->input);
	} else {
		/* finished - wait for disconnection from imap before finishing.
		   this way the old imap process will have time to destroy
		   itself before we have a chance to create another one. */
		client->finished = TRUE;
	}
	o_stream_nsend_str(conn->output, "+\n");
	return 1;
}

void imap_hibernate_client_create(int fd, bool debug)
{
	struct imap_hibernate_client *client;

	client = i_new(struct imap_hibernate_client, 1);
	client->debug = debug;
	client->conn.unix_socket = TRUE;
	connection_init_server(hibernate_clients, &client->conn,
			       "imap-hibernate", fd, fd);
	i_stream_unix_set_read_fd(client->conn.input);
}

static struct connection_settings client_set = {
	.service_name_in = "imap-hibernate",
	.service_name_out = "imap-hibernate",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = imap_hibernate_client_destroy,
	.input_line = imap_hibernate_client_input_line
};

void imap_hibernate_clients_init(void)
{
	hibernate_clients = connection_list_init(&client_set, &client_vfuncs);
}

void imap_hibernate_clients_deinit(void)
{
	connection_list_deinit(&hibernate_clients);
}
