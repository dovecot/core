/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "connection.h"
#include "istream.h"
#include "istream-unix.h"
#include "ostream.h"
#include "base64.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "time-util.h"
#include "process-title.h"
#include "master-service.h"
#include "mail-storage-service.h"
#include "imap-client.h"
#include "imap-state.h"
#include "imap-master-client.h"

struct imap_master_client {
	struct connection conn;
	bool imap_client_created;
};

struct imap_master_input {
	/* input we've already read from the IMAP client. */
	buffer_t *client_input;
	/* output that imap-hibernate was supposed to send to IMAP client,
	   but couldn't send it yet. */
	buffer_t *client_output;
	/* IMAP connection state */
	buffer_t *state;
	/* command tag */
	const char *tag;
	/* Timestamp when hibernation started */
	struct timeval hibernation_start_time;

	dev_t peer_dev;
	ino_t peer_ino;

	bool state_import_bad_idle_done;
	bool state_import_idle_continue;
};

static struct connection_list *master_clients = NULL;

static void imap_master_client_destroy(struct connection *conn)
{
	struct imap_master_client *client = (struct imap_master_client *)conn;

	if (!client->imap_client_created)
		master_service_client_connection_destroyed(master_service);
	connection_deinit(conn);
	i_free(conn);
}

static int
imap_master_client_parse_input(const char *const *args, pool_t pool,
			       struct mail_storage_service_input *input_r,
			       struct imap_master_input *master_input_r,
			       const char **error_r)
{
	const char *key, *value;
	unsigned int peer_dev_major = 0, peer_dev_minor = 0;

	i_zero(input_r);
	i_zero(master_input_r);
	master_input_r->client_input = buffer_create_dynamic(pool, 64);
	master_input_r->client_output = buffer_create_dynamic(pool, 16);
	master_input_r->state = buffer_create_dynamic(pool, 512);

	input_r->service = "imap";
	/* we never want to do userdb lookup again when restoring the client.
	   we have the userdb_fields cached already. */
	input_r->flags_override_remove = MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;

	if (args[0] == NULL) {
		*error_r = "Missing username in input";
		return -1;
	}
	input_r->username = args[0];

	for (args++; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value != NULL)
			key = t_strdup_until(*args, value++);
		else {
			key = *args;
			value = "";
		}
		if (strcmp(key, "lip") == 0) {
			if (net_addr2ip(value, &input_r->local_ip) < 0) {
				*error_r = t_strdup_printf(
					"Invalid lip value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "lport") == 0) {
			if (net_str2port(value, &input_r->local_port) < 0) {
				*error_r = t_strdup_printf(
					"Invalid lport value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "rip") == 0) {
			if (net_addr2ip(value, &input_r->remote_ip) < 0) {
				*error_r = t_strdup_printf(
					"Invalid rip value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "rport") == 0) {
			if (net_str2port(value, &input_r->remote_port) < 0) {
				*error_r = t_strdup_printf(
					"Invalid rport value: %s", value);
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
			if (str_to_ino(value, &master_input_r->peer_ino) < 0) {
				*error_r = t_strdup_printf(
					"Invalid peer_ino value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "session") == 0) {
			input_r->session_id = value;
		} else if (strcmp(key, "session_created") == 0) {
			if (str_to_time(value, &input_r->session_create_time) < 0) {
				*error_r = t_strdup_printf(
					"Invalid session_created value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "hibernation_started") == 0) {
			if (str_to_timeval(value, &master_input_r->hibernation_start_time) < 0) {
				*error_r = t_strdup_printf(
					"Invalid hibernation_started value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "userdb_fields") == 0) {
			input_r->userdb_fields =
				t_strsplit_tabescaped(value);
		} else if (strcmp(key, "client_input") == 0) {
			if (base64_decode(value, strlen(value),
					  master_input_r->client_input) < 0) {
				*error_r = t_strdup_printf(
					"Invalid client_input base64 value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "client_output") == 0) {
			if (base64_decode(value, strlen(value),
					  master_input_r->client_output) < 0) {
				*error_r = t_strdup_printf(
					"Invalid client_output base64 value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "state") == 0) {
			if (base64_decode(value, strlen(value),
					  master_input_r->state) < 0) {
				*error_r = t_strdup_printf(
					"Invalid state base64 value: %s", value);
				return -1;
			}
		} else if (strcmp(key, "tag") == 0) {
			master_input_r->tag = t_strdup(value);
		} else if (strcmp(key, "bad-done") == 0) {
			master_input_r->state_import_bad_idle_done = TRUE;
		} else if (strcmp(key, "idle-continue") == 0) {
			master_input_r->state_import_idle_continue = TRUE;
		}
	}
	if (peer_dev_major != 0 || peer_dev_minor != 0) {
		master_input_r->peer_dev =
			makedev(peer_dev_major, peer_dev_minor);
	}
	return 0;
}

static int imap_master_client_verify(const struct imap_master_input *master_input,
				     int fd_client, const char **error_r)
{
	struct stat peer_st;

	if (master_input->peer_ino == 0)
		return 0;

	/* make sure we have the right fd */
	if (fstat(fd_client, &peer_st) < 0) {
		*error_r = t_strdup_printf("fstat(peer) failed: %m");
		return -1;
	}
	if (peer_st.st_ino != master_input->peer_ino ||
	    !CMP_DEV_T(peer_st.st_dev, master_input->peer_dev)) {
		*error_r = t_strdup_printf(
			"BUG: Expected peer device=%lu,%lu inode=%s doesn't match "
			"client fd's actual device=%lu,%lu inode=%s",
			(unsigned long)major(peer_st.st_dev),
			(unsigned long)minor(peer_st.st_dev), dec2str(peer_st.st_ino),
			(unsigned long)major(master_input->peer_dev),
			(unsigned long)minor(master_input->peer_dev),
			dec2str(master_input->peer_ino));
		return -1;
	}
	return 0;
}

static int
imap_master_client_input_args(struct connection *conn, const char *const *args,
			      int fd_client, pool_t pool)
{
	struct imap_master_client *client = (struct imap_master_client *)conn;
	struct client *imap_client;
	struct mail_storage_service_input input;
	struct imap_master_input master_input;
	const char *error = NULL, *reason;
	int ret;

	if (imap_master_client_parse_input(args, pool, &input, &master_input,
					   &error) < 0) {
		e_error(conn->event, "imap-master: Failed to parse client input: %s", error);
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"-Failed to parse client input: %s\n", error));
		i_close_fd(&fd_client);
		return -1;
	}
	if (imap_master_client_verify(&master_input, fd_client, &error) < 0) {
		e_error(conn->event, "imap-master: Failed to verify client input: %s", error);
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"-Failed to verify client input: %s\n", error));
		i_close_fd(&fd_client);
		return -1;
	}
	process_title_set("[unhibernating]");

	/* NOTE: before client_create_from_input() on failures we need to close
	   fd_client, but afterward it gets closed by client_destroy() */
	ret = client_create_from_input(&input, fd_client, fd_client,
				       TRUE, &imap_client, &error);
	if (ret < 0) {
		e_error(conn->event,
			"imap-master(%s): Failed to create client: %s",
			input.username, error);
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"-Failed to create client: %s\n", error));
		i_close_fd(&fd_client);
		return -1;
	}
	client->imap_client_created = TRUE;

	long long hibernation_usecs =
		timeval_diff_usecs(&ioloop_timeval,
				   &master_input.hibernation_start_time);
	struct event *event = event_create(imap_client->event);
	event_set_name(event, "imap_client_unhibernated");
	event_add_int(event, "hibernation_usecs", hibernation_usecs);
	imap_client->state_import_bad_idle_done =
		master_input.state_import_bad_idle_done;
	imap_client->state_import_idle_continue =
		master_input.state_import_idle_continue;
	if (imap_client->state_import_bad_idle_done) {
		reason = "IDLE was stopped with BAD command";
		event_add_str(event, "reason", "idle_bad_reply");
	} else if (imap_client->state_import_idle_continue) {
		reason = "mailbox changes need to be sent";
		event_add_str(event, "reason", "mailbox_changes");
	} else {
		reason = "IDLE was stopped with DONE";
		event_add_str(event, "reason", "idle_done");
	}

	/* Send a success notification before we start anything that lasts
	   potentially a long time. imap-hibernate process is waiting for us
	   to answer. Even if we fail later, we log the error anyway. From now
	   on it's our responsibility to also log the imap_client_unhibernated
	   event. */
	o_stream_nsend_str(conn->output, "+\n");
	(void)o_stream_flush(conn->output);

	if (master_input.client_input->used > 0) {
		client_add_istream_prefix(imap_client,
					  master_input.client_input->data,
					  master_input.client_input->used);
	}

	client_create_finish_io(imap_client);
	if (client_create_finish(imap_client, &error) < 0) {
		event_add_str(event, "error", error);
		e_error(event, "imap-master: %s", error);
		event_unref(&event);
		client_destroy(imap_client, error);
		return -1;
	}
	/* log prefix is set at this point, so we don't need to add the
	   username anymore to the log messages */

	o_stream_nsend(imap_client->output,
		       master_input.client_output->data,
		       master_input.client_output->used);

	struct event_reason *event_reason =
		event_reason_begin("imap:unhibernate");
	ret = imap_state_import_internal(imap_client, master_input.state->data,
					 master_input.state->used, &error);
	event_reason_end(&event_reason);

	if (ret <= 0) {
		error = t_strdup_printf("Failed to import client state: %s", error);
		event_add_str(event, "error", error);
		e_error(event, "imap-master: %s", error);
		event_unref(&event);
		client_destroy(imap_client, "Client state initialization failed");
		return -1;
	}
	if (imap_client->mailbox != NULL) {
		/* Would be nice to set this earlier, but the previous errors
		   happen rarely enough that it shouldn't really matter. */
		event_add_str(event, "mailbox",
			      mailbox_get_vname(imap_client->mailbox));
	}

	if (master_input.tag != NULL)
		imap_state_import_idle_cmd_tag(imap_client, master_input.tag);

	e_debug(event, "imap-master: Unhibernated because %s "
		"(hibernated for %llu.%06llu secs)", reason,
		hibernation_usecs/1000000, hibernation_usecs%1000000);
	event_unref(&event);

	/* make sure all pending input gets handled */
	if (master_input.client_input->used > 0) {
		e_debug(imap_client->event,
			"imap-master: Pending client input: '%s'",
			str_sanitize(str_c(master_input.client_input), 128));
		io_set_pending(imap_client->io);
	}

	imap_refresh_proctitle();
	/* we'll always disconnect the client afterwards */
	return -1;
}

static int
imap_master_client_input_line(struct connection *conn, const char *line)
{
	char *const *args;
	pool_t pool;
	int fd_client, ret;

	if (!conn->version_received) {
		if (connection_handshake_args_default(conn, t_strsplit_tabescaped(line)) < 0)
			return -1;
		conn->version_received = TRUE;
		return 1;
	}

	fd_client = i_stream_unix_get_read_fd(conn->input);
	if (fd_client == -1) {
		e_error(conn->event, "imap-master: IMAP client fd not received");
		return -1;
	}

	if (imap_debug)
		e_debug(conn->event, "imap-master: Client input: %s", line);

	pool = pool_alloconly_create("imap master client cmd", 1024);
	args = p_strsplit_tabescaped(pool, line);
	ret = imap_master_client_input_args(conn, (const void *)args,
					    fd_client, pool);
	pool_unref(&pool);
	return ret;
}

static void imap_master_client_idle_timeout(struct connection *conn)
{
	e_error(conn->event, "imap-master: Client didn't send any input for %"
		PRIdTIME_T" seconds - disconnecting",
		ioloop_time - conn->last_input_tv.tv_sec);

	conn->disconnect_reason = CONNECTION_DISCONNECT_IDLE_TIMEOUT;
	conn->v.destroy(conn);
}

void imap_master_client_create(int fd)
{
	struct imap_master_client *client;

	client = i_new(struct imap_master_client, 1);
	client->conn.unix_socket = TRUE;
	connection_init_server(master_clients, &client->conn,
			       "imap-master", fd, fd);

	/* read the first file descriptor that we can */
	i_stream_unix_set_read_fd(client->conn.input);

	imap_refresh_proctitle();
}

static struct connection_settings client_set = {
	.service_name_in = "imap-master",
	.service_name_out = "imap-master",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = FALSE,

	/* less than imap-hibernate's IMAP_MASTER_CONNECTION_TIMEOUT_MSECS */
	.input_idle_timeout_secs = 25,
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = imap_master_client_destroy,
	.input_line = imap_master_client_input_line,
	.idle_timeout = imap_master_client_idle_timeout,
};

bool imap_master_clients_refresh_proctitle(void)
{
	switch (master_clients->connections_count) {
	case 0:
		return FALSE;
	case 1:
		process_title_set("[waiting on unhibernate client]");
		return TRUE;
	default:
		process_title_set(t_strdup_printf("[unhibernating %u clients]",
			master_clients->connections_count));
		return TRUE;
	}
}

void imap_master_clients_init(void)
{
	master_clients = connection_list_init(&client_set, &client_vfuncs);
}

void imap_master_clients_deinit(void)
{
	connection_list_deinit(&master_clients);
}
