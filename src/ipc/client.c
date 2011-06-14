/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "ipc-group.h"
#include "ipc-connection.h"
#include "client.h"

#include <unistd.h>

struct client {
	struct client *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
};

static struct client *clients;

static void client_input(struct client *client);

static void
client_cmd_input(enum ipc_cmd_status status, const char *line, void *context)
{
	struct client *client = context;
	char chr = '\0';

	switch (status) {
	case IPC_CMD_STATUS_REPLY:
		chr = ':';
		break;
	case IPC_CMD_STATUS_OK:
		chr = '+';
		break;
	case IPC_CMD_STATUS_ERROR:
		chr = '-';
		break;
	}

	T_BEGIN {
		o_stream_send_str(client->output,
				  t_strdup_printf("%c%s\n", chr, line));
	} T_END;

	if (status != IPC_CMD_STATUS_REPLY && client->io == NULL) {
		client->io = io_add(client->fd, IO_READ, client_input, client);
		client_input(client);
	}
}

static void client_input(struct client *client)
{
	struct ipc_group *group;
	struct ipc_connection *conn;
	char *line, *id, *data;
	unsigned int id_num;
	bool ret;

	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		/* <ipc name> *|<id> <command> */
		id = strchr(line, '\t');
		if (id == NULL)
			data = NULL;
		else {
			*id++ = '\0';
			data = strchr(id, '\t');
		}
		if (data == NULL || data[1] == '\0') {
			o_stream_send_str(client->output, "-Invalid input\n");
			continue;
		}
		*data++ = '\0';

		group = ipc_group_lookup_name(line);

		ret = FALSE;
		if (strcmp(id, "*") == 0) {
			/* send to everyone */
			if (group == NULL) {
				client_cmd_input(IPC_CMD_STATUS_OK,
						 NULL, client);
			} else {
				ret = ipc_group_cmd(group, data,
						    client_cmd_input, client);
			}
		} else if (str_to_uint(id, &id_num) < 0) {
			o_stream_send_str(client->output,
				t_strdup_printf("-Invalid IPC connection id: %s\n", id));
			continue;
		} else if (group == NULL) {
			o_stream_send_str(client->output,
				t_strdup_printf("-Unknown IPC group: %s\n", line));
		} else if ((conn = ipc_connection_lookup_id(group, id_num)) == NULL) {
			o_stream_send_str(client->output,
				t_strdup_printf("-Unknown IPC connection id: %u\n", id_num));
			continue;
		} else {
			ipc_connection_cmd(conn, data, client_cmd_input, client);
			ret = TRUE;
		}

		if (ret) {
			/* we'll handle commands one at a time. stop reading
			   input until this command is finished. */
			io_remove(&client->io);
			break;
		}
	}
	if (client->input->eof || client->input->stream_errno != 0)
		client_destroy(&client);
}

struct client *client_create(int fd)
{
	struct client *client;

	client = i_new(struct client, 1);
	client->fd = fd;
	client->io = io_add(fd, IO_READ, client_input, client);
	client->input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);

	DLLIST_PREPEND(&clients, client);
	return client;
}

void client_destroy(struct client **_client)
{
	struct client *client = *_client;

	*_client = NULL;

	DLLIST_REMOVE(&clients, client);
	if (client->io != NULL)
		io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	if (close(client->fd) < 0)
		i_error("close(client) failed: %m");
	i_free(client);

	master_service_client_connection_destroyed(master_service);
}

void clients_destroy_all(void)
{
	while (clients != NULL) {
		struct client *client = clients;

		client_destroy(&client);
	}
}
