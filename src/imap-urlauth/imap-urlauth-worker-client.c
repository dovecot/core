/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "fdpass.h"
#include "eacces-error.h"

#include "imap-urlauth-common.h"
#include "imap-urlauth-worker-client.h"

/* max. length of input lines (URLs) */
#define MAX_INBUF_SIZE 2048

enum imap_urlauth_worker_state {
	IMAP_URLAUTH_WORKER_STATE_INACTIVE = 0,
	IMAP_URLAUTH_WORKER_STATE_CONNECTED,
	IMAP_URLAUTH_WORKER_STATE_ACTIVE,
};

struct imap_urlauth_worker_client {
	struct client *client;
	int fd_ctrl;
	struct io *ctrl_io;
	struct ostream *ctrl_output;
	struct istream *ctrl_input;
	struct event *event;

	enum imap_urlauth_worker_state worker_state;

	bool disconnected:1;
};

static void client_worker_input(struct imap_urlauth_worker_client *wclient);

struct imap_urlauth_worker_client *
imap_urlauth_worker_client_init(struct client *client)
{
	struct imap_urlauth_worker_client *wclient;

	wclient = i_new(struct imap_urlauth_worker_client, 1);
	wclient->client = client;
	wclient->fd_ctrl = -1;

	wclient->event = event_create(client->event);
	event_set_append_log_prefix(wclient->event, "worker: ");

	return wclient;
}

void imap_urlauth_worker_client_deinit(
	struct imap_urlauth_worker_client **_wclient)
{
	struct imap_urlauth_worker_client *wclient = *_wclient;

	if (wclient == NULL)
		return;
	*_wclient = NULL;

	imap_urlauth_worker_client_disconnect(wclient);
	event_unref(&wclient->event);
	i_free(wclient);
}

int imap_urlauth_worker_client_connect(
	struct imap_urlauth_worker_client *wclient)
{
	struct client *client = wclient->client;
	static const char handshake[] = "VERSION\timap-urlauth-worker\t2\t0\n";
	const char *socket_path;
	ssize_t ret;
	unsigned char data;

	socket_path = t_strconcat(client->set->base_dir,
				  "/"IMAP_URLAUTH_WORKER_SOCKET, NULL);

	e_debug(wclient->event, "Connecting to worker socket %s", socket_path);

	wclient->fd_ctrl = net_connect_unix_with_retries(socket_path, 1000);
	if (wclient->fd_ctrl < 0) {
		if (errno == EACCES) {
			e_error(wclient->event, "imap-urlauth-client: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			e_error(wclient->event, "imap-urlauth-client: "
				"net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return -1;
	}

	/* transfer one or two fds */
	data = (client->fd_in == client->fd_out ? '0' : '1');
	ret = fd_send(wclient->fd_ctrl, client->fd_in, &data, sizeof(data));
	if (ret > 0 && client->fd_in != client->fd_out) {
		data = '0';
		ret = fd_send(wclient->fd_ctrl, client->fd_out,
			      &data, sizeof(data));
	}

	if (ret <= 0) {
		if (ret < 0) {
			e_error(wclient->event,
				"fd_send(%s, %d) failed: %m",
				socket_path, wclient->fd_ctrl);
		} else {
			e_error(wclient->event,
				"fd_send(%s, %d) failed to send byte",
				socket_path, wclient->fd_ctrl);
		}
		imap_urlauth_worker_client_disconnect(wclient);
		return -1;
	}

	wclient->ctrl_output = o_stream_create_fd(wclient->fd_ctrl, SIZE_MAX);

	/* send protocol version handshake */
	if (o_stream_send_str(wclient->ctrl_output, handshake) < 0) {
		e_error(wclient->event,
			"Error sending handshake to imap-urlauth worker: %m");
		imap_urlauth_worker_client_disconnect(wclient);
		return -1;
	}

	wclient->ctrl_input =
		i_stream_create_fd(wclient->fd_ctrl, MAX_INBUF_SIZE);
	wclient->ctrl_io =
		io_add(wclient->fd_ctrl, IO_READ, client_worker_input, wclient);
	return 0;
}

void imap_urlauth_worker_client_disconnect(
	struct imap_urlauth_worker_client *wclient)
{
	wclient->worker_state = IMAP_URLAUTH_WORKER_STATE_INACTIVE;

	io_remove(&wclient->ctrl_io);
	o_stream_destroy(&wclient->ctrl_output);
	i_stream_destroy(&wclient->ctrl_input);
	if (wclient->fd_ctrl >= 0) {
		net_disconnect(wclient->fd_ctrl);
		wclient->fd_ctrl = -1;
	}
}

static void
imap_urlauth_worker_client_error(struct imap_urlauth_worker_client *wclient,
				 const char *error)
{
	client_disconnect(wclient->client, error);
	imap_urlauth_worker_client_disconnect(wclient);
}

static int
client_worker_input_line(struct imap_urlauth_worker_client *wclient,
			 const char *response)
{
	struct client *client = wclient->client;
	const char *const *apps;
	unsigned int count, i;
	bool restart;
	string_t *str;
	int ret;

	switch (wclient->worker_state) {
	case IMAP_URLAUTH_WORKER_STATE_INACTIVE:
		if (strcasecmp(response, "OK") != 0) {
			imap_urlauth_worker_client_error(
				wclient, "Worker handshake failed");
			return -1;
		}
		wclient->worker_state = IMAP_URLAUTH_WORKER_STATE_CONNECTED;

		str = t_str_new(256);
		str_append(str, "ACCESS\t");
		if (client->username != NULL)
			str_append_tabescaped(str, client->username);
		str_append(str, "\t");
		str_append_tabescaped(str, client->service);
		if (client->set->mail_debug)
			str_append(str, "\tdebug");
		if (array_count(&client->access_apps) > 0) {
			str_append(str, "\tapps=");
			apps = array_get(&client->access_apps, &count);
			str_append(str, apps[0]);
			for (i = 1; i < count; i++) {
				str_append_c(str, ',');
				str_append_tabescaped(str, apps[i]);
			}
		}
		str_append(str, "\n");

		ret = o_stream_send(wclient->ctrl_output,
				    str_data(str), str_len(str));
		i_assert(ret < 0 || (size_t)ret == str_len(str));
		if (ret < 0) {
			imap_urlauth_worker_client_error(wclient,
				"Failed to send ACCESS control command to worker");
			return -1;
		}
		break;

	case IMAP_URLAUTH_WORKER_STATE_CONNECTED:
		if (strcasecmp(response, "OK") != 0) {
			imap_urlauth_worker_client_error(wclient,
				"Failed to negotiate access parameters");
			return -1;
		}
		wclient->worker_state = IMAP_URLAUTH_WORKER_STATE_ACTIVE;
		break;

	case IMAP_URLAUTH_WORKER_STATE_ACTIVE:
		restart = TRUE;
		if (strcasecmp(response, "DISCONNECTED") == 0) {
			/* worker detected client disconnect */
			restart = FALSE;
		} else if (strcasecmp(response, "FINISHED") != 0) {
			/* unknown response */
			imap_urlauth_worker_client_error(wclient,
				"Worker finished with unknown response");
			return -1;
		}

		e_debug(wclient->event, "Worker finished successfully");

		if (restart) {
			/* connect to new worker for accessing different user */
			imap_urlauth_worker_client_disconnect(wclient);
			if (imap_urlauth_worker_client_connect(wclient) < 0) {
				imap_urlauth_worker_client_error(wclient,
					"Failed to connect to new worker");
				return -1;
			}

			/* indicate success of "END" command */
			client_send_line(client, "OK");
		} else {
			imap_urlauth_worker_client_error(
				wclient, "Client disconnected");
		}
		return -1;
 	default:
		i_unreached();
	}
	return 0;
}

static void client_worker_input(struct imap_urlauth_worker_client *wclient)
{
	struct istream *input = wclient->ctrl_input;
	const char *line;

	if (input->closed) {
		/* disconnected */
		imap_urlauth_worker_client_error(
			wclient, "Worker disconnected unexpectedly");
		return;
	}

	switch (i_stream_read(input)) {
	case -1:
		/* disconnected */
		imap_urlauth_worker_client_error(
			wclient, "Worker disconnected unexpectedly");
		return;
	case -2:
		/* input buffer full */
		imap_urlauth_worker_client_error(
			wclient, "Worker sent too large input");
		return;
	}

	while ((line = i_stream_next_line(input)) != NULL) {
		if (client_worker_input_line(wclient, line) < 0)
			return;
	}
}
