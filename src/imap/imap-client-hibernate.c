/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "fdpass.h"
#include "net.h"
#include "ostream.h"
#include "write-full.h"
#include "base64.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "mailbox-watch.h"
#include "imap-state.h"
#include "imap-client.h"

#include <sys/stat.h>

#define IMAP_HIBERNATE_SOCKET_NAME "imap-hibernate"
#define IMAP_HIBERNATE_SEND_TIMEOUT_SECS 10
#define IMAP_HIBERNATE_HANDSHAKE "VERSION\timap-hibernate\t1\t0\n"

static int imap_hibernate_handshake(int fd, const char *path)
{
	char buf[1024];
	ssize_t ret;

	if (write_full(fd, IMAP_HIBERNATE_HANDSHAKE,
		       strlen(IMAP_HIBERNATE_HANDSHAKE)) < 0) {
		i_error("write(%s) failed: %m", path);
		return -1;
	} else if ((ret = read(fd, buf, sizeof(buf)-1)) < 0) {
		i_error("read(%s) failed: %m", path);
		return -1;
	} else if (ret > 0 && buf[ret-1] == '\n') {
		buf[ret-1] = '\0';
		if (version_string_verify(buf, "imap-hibernate", 1))
			return 0;
	}
	i_error("%s sent invalid VERSION handshake: %s", path, buf);
	return -1;
}

static void imap_hibernate_write_cmd(struct client *client, string_t *cmd,
				     const buffer_t *state, int fd_notify)
{
	struct mail_user *user = client->user;
	struct stat peer_st;
	const char *tag;

	tag = client->command_queue == NULL ? NULL : client->command_queue->tag;

	str_append_tabescaped(cmd, user->username);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, user->set->mail_log_prefix);
	str_printfa(cmd, "\tidle_notify_interval=%u",
		    client->set->imap_idle_notify_interval);
	if (fstat(client->fd_in, &peer_st) == 0) {
		str_printfa(cmd, "\tpeer_dev_major=%lu\tpeer_dev_minor=%lu\tpeer_ino=%llu",
			    (unsigned long)major(peer_st.st_dev),
			    (unsigned long)minor(peer_st.st_dev),
			    (unsigned long long)peer_st.st_ino);
	}

	str_append(cmd, "\tsession=");
	str_append_tabescaped(cmd, user->session_id);
	if (user->session_create_time != 0) {
		str_printfa(cmd, "\tsession_created=%s",
			    dec2str(user->session_create_time));
	}
	if (user->conn.local_ip != NULL)
		str_printfa(cmd, "\tlip=%s", net_ip2addr(user->conn.local_ip));
	if (user->conn.remote_ip != NULL)
		str_printfa(cmd, "\trip=%s", net_ip2addr(user->conn.remote_ip));
	if (client->userdb_fields != NULL) {
		string_t *userdb_fields = t_str_new(256);
		unsigned int i;

		for (i = 0; client->userdb_fields[i] != NULL; i++) {
			if (i > 0)
				str_append_c(userdb_fields, '\t');
			str_append_tabescaped(userdb_fields, client->userdb_fields[i]);
		}
		str_append(cmd, "\tuserdb_fields=");
		str_append_tabescaped(cmd, str_c(userdb_fields));
	}
	if (user->uid != (uid_t)-1)
		str_printfa(cmd, "\tuid=%s", dec2str(user->uid));
	if (user->gid != (gid_t)-1)
		str_printfa(cmd, "\tgid=%s", dec2str(user->gid));
	if (tag != NULL)
		str_printfa(cmd, "\ttag=%s", tag);
	str_append(cmd, "\tstats=");
	str_append_tabescaped(cmd, client_stats(client));
	if (client->command_queue != NULL &&
	    strcasecmp(client->command_queue->name, "IDLE") == 0)
		str_append(cmd, "\tidle-cmd");
	if (fd_notify != -1)
		str_append(cmd, "\tnotify_fd");
	str_append(cmd, "\tstate=");
	base64_encode(state->data, state->used, cmd);
	str_append_c(cmd, '\n');
}

static int
imap_hibernate_process_send_cmd(int fd_socket, const char *path,
				const string_t *cmd, int fd_client)
{
	ssize_t ret;

	i_assert(fd_socket != -1);
	i_assert(str_len(cmd) > 1);

	if (imap_hibernate_handshake(fd_socket, path) < 0)
		return -1;
	if ((ret = fd_send(fd_socket, fd_client, str_data(cmd), 1)) < 0) {
		i_error("fd_send(%s) failed: %m", path);
		return -1;
	}
	if ((ret = write_full(fd_socket, str_data(cmd)+1, str_len(cmd)-1)) < 0) {
		i_error("write(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static int imap_hibernate_process_read(int fd, const char *path)
{
	char buf[1024];
	ssize_t ret;

	if ((ret = read(fd, buf, sizeof(buf)-1)) < 0) {
		i_error("read(%s) failed: %m", path);
		return -1;
	} else if (ret == 0) {
		i_error("%s disconnected", path);
		return -1;
	} else if (buf[0] != '+') {
		buf[ret] = '\0';
		i_error("%s returned failure: %s", path,
			ret > 0 && buf[0] == '-' ? buf+1 : buf);
		return -1;
	} else {
		return 0;
	}
}

static int
imap_hibernate_process_send(struct client *client,
			    const buffer_t *state, int fd_notify, int *fd_r)
{
	string_t *cmd = t_str_new(512);
	const char *path;
	ssize_t ret = 0;
	int fd;

	i_assert(state->used > 0);

	*fd_r = -1;

	path = t_strconcat(client->user->set->base_dir,
			   "/"IMAP_HIBERNATE_SOCKET_NAME, NULL);
	fd = net_connect_unix_with_retries(path, 1000);
	if (fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", path);
		return -1;
	}
	net_set_nonblock(fd, FALSE);

	imap_hibernate_write_cmd(client, cmd, state, fd_notify);

	alarm(IMAP_HIBERNATE_SEND_TIMEOUT_SECS);
	if (imap_hibernate_process_send_cmd(fd, path, cmd, client->fd_in) < 0 ||
	    imap_hibernate_process_read(fd, path) < 0)
		ret = -1;
	else if (fd_notify != -1) {
		if ((ret = fd_send(fd, fd_notify, "\n", 1)) < 0)
			i_error("fd_send(%s) failed: %m", path);
		else
			ret = imap_hibernate_process_read(fd, path);
	}
	alarm(0);
	if (ret < 0) {
		net_disconnect(fd);
		return -1;
	}
	*fd_r = fd;
	return 0;
}

bool imap_client_hibernate(struct client **_client)
{
	struct client *client = *_client;
	buffer_t *state;
	const char *error;
	int ret, fd_notify = -1, fd_hibernate = -1;

	if (client->fd_in != client->fd_out) {
		/* we won't try to hibernate stdio clients */
		return FALSE;
	}
	if (o_stream_get_buffer_used_size(client->output) > 0) {
		/* wait until we've sent the pending output to client */
		return FALSE;
	}

	state = buffer_create_dynamic(default_pool, 1024);
	ret = imap_state_export_internal(client, state, &error);
	if (ret < 0) {
		i_error("Couldn't hibernate imap client: "
			"Couldn't export state: %s (mailbox=%s)", error,
			client->mailbox == NULL ? "" :
			mailbox_get_vname(client->mailbox));
	} else if (ret == 0) {
		e_debug(client->event, "Couldn't hibernate imap client: "
			"Couldn't export state: %s (mailbox=%s)", error,
			client->mailbox == NULL ? "" :
			mailbox_get_vname(client->mailbox));
	}
	if (ret > 0 && client->mailbox != NULL) {
		fd_notify = mailbox_watch_extract_notify_fd(client->mailbox,
							    &error);
		if (fd_notify == -1) {
			e_debug(client->event, "Couldn't hibernate imap client: "
				"Couldn't extract notifications fd: %s",
				error);
			ret = -1;
		}
	}
	if (ret > 0) {
		if (imap_hibernate_process_send(client, state, fd_notify, &fd_hibernate) < 0)
			ret = -1;
	}
	i_close_fd(&fd_notify);
	if (ret > 0) {
		/* hide the disconnect log message, because the client didn't
		   actually log out */
		e_debug(client->event,
			"Successfully hibernated imap client in mailbox %s",
			client->mailbox == NULL ? "<none>" :
			mailbox_get_vname(client->mailbox));
		client->disconnected = TRUE;
		client->hibernated = TRUE;
		client_destroy(client, NULL);
		*_client = NULL;
	}
	/* notify imap-hibernate that we're done by closing the connection.
	   do this only after client is destroyed. this way imap-hibernate
	   won't try to launch another imap process too early and cause
	   problems (like sending duplicate session ID to stats process) */
	if (fd_hibernate != -1)
		net_disconnect(fd_hibernate);
	buffer_free(&state);
	return ret > 0;
}
