static int client_worker_connect(struct client *client)
{
	static const char handshake[] = "VERSION\timap-urlauth-worker\t2\t0\n";
	const char *socket_path;
	ssize_t ret;
	unsigned char data;

	socket_path = t_strconcat(client->set->base_dir,
				  "/"IMAP_URLAUTH_WORKER_SOCKET, NULL);

	e_debug(client->event, "Connecting to worker socket %s", socket_path);

	client->fd_ctrl = net_connect_unix_with_retries(socket_path, 1000);
	if (client->fd_ctrl < 0) {
		if (errno == EACCES) {
			e_error(client->event, "imap-urlauth-client: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			e_error(client->event, "imap-urlauth-client: "
				"net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return -1;
	}

	/* transfer one or two fds */
	data = (client->fd_in == client->fd_out ? '0' : '1');
	ret = fd_send(client->fd_ctrl, client->fd_in, &data, sizeof(data));
	if (ret > 0 && client->fd_in != client->fd_out) {
		data = '0';
		ret = fd_send(client->fd_ctrl, client->fd_out,
			      &data, sizeof(data));
	}

	if (ret <= 0) {
		if (ret < 0) {
			e_error(client->event,
				"fd_send(%s, %d) failed: %m",
				socket_path, client->fd_ctrl);
		} else {
			e_error(client->event,
				"fd_send(%s, %d) failed to send byte",
				socket_path, client->fd_ctrl);
		}
		client_worker_disconnect(client);
		return -1;
	}

	client->ctrl_output = o_stream_create_fd(client->fd_ctrl, SIZE_MAX);

	/* send protocol version handshake */
	if (o_stream_send_str(client->ctrl_output, handshake) < 0) {
		e_error(client->event,
			"Error sending handshake to imap-urlauth worker: %m");
		client_worker_disconnect(client);
		return -1;
	}

	client->ctrl_input =
		i_stream_create_fd(client->fd_ctrl, MAX_INBUF_SIZE);
	client->ctrl_io =
		io_add(client->fd_ctrl, IO_READ, client_worker_input, client);
	return 0;
}

void client_worker_disconnect(struct client *client)
{
	client->worker_state = IMAP_URLAUTH_WORKER_STATE_INACTIVE;

	io_remove(&client->ctrl_io);
	o_stream_destroy(&client->ctrl_output);
	i_stream_destroy(&client->ctrl_input);
	if (client->fd_ctrl >= 0) {
		net_disconnect(client->fd_ctrl);
		client->fd_ctrl = -1;
	}
}

static int
client_worker_input_line(struct client *client, const char *response)
{
	const char *const *apps;
	unsigned int count, i;
	bool restart;
	string_t *str;
	int ret;

	switch (client->worker_state) {
	case IMAP_URLAUTH_WORKER_STATE_INACTIVE:
		if (strcasecmp(response, "OK") != 0) {
			client_disconnect(client, "Worker handshake failed");
			return -1;
		}
		client->worker_state = IMAP_URLAUTH_WORKER_STATE_CONNECTED;

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

		ret = o_stream_send(client->ctrl_output,
				    str_data(str), str_len(str));
		i_assert(ret < 0 || (size_t)ret == str_len(str));
		if (ret < 0) {
			client_disconnect(client,
				"Failed to send ACCESS control command to worker");
			return -1;
		}
		break;

	case IMAP_URLAUTH_WORKER_STATE_CONNECTED:
		if (strcasecmp(response, "OK") != 0) {
			client_disconnect(client,
				"Failed to negotiate access parameters");
			return -1;
		}
		client->worker_state = IMAP_URLAUTH_WORKER_STATE_ACTIVE;
		break;

	case IMAP_URLAUTH_WORKER_STATE_ACTIVE:
		restart = TRUE;
		if (strcasecmp(response, "DISCONNECTED") == 0) {
			/* worker detected client disconnect */
			restart = FALSE;
		} else if (strcasecmp(response, "FINISHED") != 0) {
			/* unknown response */
			client_disconnect(client,
				"Worker finished with unknown response");
			return -1;
		}

		e_debug(client->event, "Worker finished successfully");

		if (restart) {
			/* connect to new worker for accessing different user */
			client_worker_disconnect(client);
			if (client_worker_connect(client) < 0) {
				client_disconnect(client,
					"Failed to connect to new worker");
				return -1;
			}

			/* indicate success of "END" command */
			client_send_line(client, "OK");
		} else {
			client_disconnect(client, "Client disconnected");
		}
		return -1;
 	default:
		i_unreached();
	}
	return 0;
}

void client_worker_input(struct client *client)
{
	struct istream *input = client->ctrl_input;
	const char *line;

	if (input->closed) {
		/* disconnected */
		client_disconnect(client, "Worker disconnected unexpectedly");
		return;
	}

	switch (i_stream_read(input)) {
	case -1:
		/* disconnected */
		client_disconnect(client, "Worker disconnected unexpectedly");
		return;
	case -2:
		/* input buffer full */
		client_disconnect(client, "Worker sent too large input");
		return;
	}

	while ((line = i_stream_next_line(input)) != NULL) {
		if (client_worker_input_line(client, line) < 0)
			return;
	}
}
