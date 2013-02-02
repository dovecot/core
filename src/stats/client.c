/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "master-service.h"
#include "mail-command.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-domain.h"
#include "mail-ip.h"
#include "client-export.h"
#include "client.h"

#include <unistd.h>

#define CLIENT_MAX_SIMULTANEOUS_ITER_COUNT 1000
#define MAX_INBUF_SIZE 1024
#define OUTBUF_THROTTLE_SIZE (1024*64)

static struct client *clients;

bool client_is_busy(struct client *client)
{
	client->iter_count++;
	if (client->iter_count % CLIENT_MAX_SIMULTANEOUS_ITER_COUNT == 0)
		return TRUE;
	if (o_stream_get_buffer_used_size(client->output) < OUTBUF_THROTTLE_SIZE)
		return FALSE;
	if (o_stream_flush(client->output) < 0)
		return TRUE;
	return o_stream_get_buffer_used_size(client->output) >= OUTBUF_THROTTLE_SIZE;
}

static int
client_handle_request(struct client *client, const char *const *args,
		      const char **error_r)
{
	const char *cmd = args[0];

	if (cmd == NULL) {
		*error_r = "Missing command";
		return -1;
	}
	args++;

	if (strcmp(cmd, "EXPORT") == 0)
		return client_export(client, args, error_r);

	*error_r = "Unknown command";
	return -1;
}

static const char *const*
client_read_next_line(struct client *client)
{
	const char *line;
	char **args;
	unsigned int i;

	line = i_stream_next_line(client->input);
	if (line == NULL)
		return NULL;

	args = p_strsplit(pool_datastack_create(), line, "\t");
	for (i = 0; args[i] != NULL; i++)
		args[i] = str_tabunescape(args[i]);
	return (void *)args;
}

static void client_input(struct client *client)
{
	const char *const *args, *error;
	int ret;

	if (client->to_pending != NULL)
		timeout_remove(&client->to_pending);

	switch (i_stream_read(client->input)) {
	case -2:
		i_error("BUG: Stats client sent too much data");
		client_destroy(&client);
		return;
	case -1:
		client_destroy(&client);
		return;
	}

	o_stream_cork(client->output);
	while ((args = client_read_next_line(client)) != NULL) {
		ret = client_handle_request(client, args, &error);
		if (ret < 0) {
			i_error("Stats client input error: %s", error);
			client_destroy(&client);
			return;
		}
		if (ret == 0) {
			o_stream_set_flush_pending(client->output, TRUE);
			io_remove(&client->io);
			break;
		}
		client->cmd_more = NULL;
	}
	o_stream_uncork(client->output);
}

static int client_output(struct client *client)
{
	int ret = 1;

	o_stream_cork(client->output);
	if (o_stream_flush(client->output) < 0) {
		client_destroy(&client);
		return 1;
	}
	if (client->cmd_more != NULL)
		ret = client->cmd_more(client);
	o_stream_uncork(client->output);

	if (ret > 0) {
		client->cmd_more = NULL;
		if (client->io == NULL)
			client_enable_io(client);
	}
	return ret;
}

void client_enable_io(struct client *client)
{
	i_assert(client->io == NULL);

	client->io = io_add(client->fd, IO_READ, client_input, client);
	if (client->to_pending == NULL)
		client->to_pending = timeout_add(0, client_input, client);
}

struct client *client_create(int fd)
{
	struct client *client;

	client = i_new(struct client, 1);
	client->fd = fd;
	client->io = io_add(fd, IO_READ, client_input, client);
	client->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_set_flush_callback(client->output, client_output, client);
	client->cmd_pool = pool_alloconly_create("cmd pool", 1024);

	DLLIST_PREPEND(&clients, client);
	return client;
}

static void client_unref_iters(struct client *client)
{
	if (client->mail_cmd_iter != NULL)
		mail_command_unref(&client->mail_cmd_iter);
	if (client->mail_session_iter != NULL)
		mail_session_unref(&client->mail_session_iter);
	if (client->mail_user_iter != NULL)
		mail_user_unref(&client->mail_user_iter);
	if (client->mail_domain_iter != NULL)
		mail_domain_unref(&client->mail_domain_iter);
	if (client->mail_ip_iter != NULL)
		mail_ip_unref(&client->mail_ip_iter);
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

	client_unref_iters(client);
	pool_unref(&client->cmd_pool);
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
