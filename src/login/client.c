/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "hash.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "process-title.h"
#include "safe-memset.h"
#include "strescape.h"
#include "imap-parser.h"
#include "client.h"
#include "client-authenticate.h"
#include "ssl-proxy.h"

#include <syslog.h>

/* max. size of one parameter in line */
#define MAX_INBUF_SIZE 512

/* max. number of IMAP argument elements to accept. The maximum memory usage
   for command from user is around MAX_INBUF_SIZE * MAX_IMAP_ARG_ELEMENTS */
#define MAX_IMAP_ARG_ELEMENTS 4

/* Disconnect client after idling this many seconds */
#define CLIENT_LOGIN_IDLE_TIMEOUT 60

/* When max. number of simultaneous connections is reached, few of the
   oldest connections are disconnected. Since we have to go through the whole
   client hash, it's faster if we disconnect multiple clients. */
#define CLIENT_DESTROY_OLDEST_COUNT 16

static struct hash_table *clients;
static struct timeout *to_idle;

static void client_set_title(struct client *client)
{
	const char *host;

	if (!verbose_proctitle || !process_per_connection)
		return;

	host = net_ip2host(&client->ip);
	if (host == NULL)
		host = "??";

	process_title_set(t_strdup_printf(client->tls ? "[%s TLS]" : "[%s]",
					  host));
}

static int cmd_capability(struct client *client)
{
	const char *capability;

	capability = t_strconcat("* CAPABILITY " CAPABILITY_STRING,
				 ssl_initialized ? " STARTTLS" : "",
				 disable_plaintext_auth && !client->tls ?
				 " LOGINDISABLED" : "",
				 client_authenticate_get_capabilities(),
				 NULL);
	client_send_line(client, capability);
	client_send_tagline(client, "OK Capability completed.");
	return TRUE;
}

static int cmd_starttls(struct client *client)
{
	int fd_ssl;

	if (client->tls) {
		client_send_tagline(client, "BAD TLS is already active.");
		return TRUE;
	}

	if (!ssl_initialized) {
		client_send_tagline(client, "BAD TLS support isn't enabled.");
		return TRUE;
	}

	client_send_tagline(client, "OK Begin TLS negotiation now.");
	o_stream_flush(client->output);

	/* must be removed before ssl_proxy_new(), since it may
	   io_add() the same fd. */
	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	fd_ssl = ssl_proxy_new(client->fd);
	if (fd_ssl != -1) {
		client->tls = TRUE;
                client_set_title(client);

		client->fd = fd_ssl;

		i_stream_unref(client->input);
		o_stream_unref(client->output);

		client->input = i_stream_create_file(fd_ssl, default_pool,
						     8192, FALSE);
		client->output = o_stream_create_file(fd_ssl, default_pool,
						      1024, IO_PRIORITY_DEFAULT,
						      FALSE);
	} else {
		client_send_line(client, " * BYE TLS handehake failed.");
		client_destroy(client, "TLS handshake failed");
	}

	client->io = io_add(client->fd, IO_READ, client_input, client);
	return TRUE;
}

static int cmd_noop(struct client *client)
{
	client_send_tagline(client, "OK NOOP completed.");
	return TRUE;
}

static int cmd_logout(struct client *client)
{
	client_send_line(client, "* BYE Logging out");
	client_send_tagline(client, "OK Logout completed.");
	client_destroy(client, "Aborted login");
	return TRUE;
}

static int client_command_execute(struct client *client, const char *cmd,
				  struct imap_arg *args)
{
	cmd = str_ucase(t_strdup_noconst(cmd));
	if (strcmp(cmd, "LOGIN") == 0)
		return cmd_login(client, args);
	if (strcmp(cmd, "AUTHENTICATE") == 0)
		return cmd_authenticate(client, args);
	if (strcmp(cmd, "CAPABILITY") == 0)
		return cmd_capability(client);
	if (strcmp(cmd, "STARTTLS") == 0)
		return cmd_starttls(client);
	if (strcmp(cmd, "NOOP") == 0)
		return cmd_noop(client);
	if (strcmp(cmd, "LOGOUT") == 0)
		return cmd_logout(client);

	return FALSE;
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
static int client_skip_line(struct client *client)
{
	const unsigned char *data;
	size_t i, data_size;

	data = i_stream_get_data(client->input, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			i_stream_skip(client->input, i+1);
			return TRUE;
		}
	}

	return FALSE;
}

static void client_handle_input(struct client *client)
{
	struct imap_arg *args;

	if (client->cmd_finished) {
		/* clear the previous command from memory. don't do this
		   immediately after handling command since we need the
		   cmd_tag to stay some time after authentication commands. */
		client->cmd_tag = NULL;
		client->cmd_name = NULL;
		imap_parser_reset(client->parser);

		/* remove \r\n */
		if (!client_skip_line(client))
			return;

		client->cmd_finished = FALSE;
	}

	if (client->cmd_tag == NULL) {
                client->cmd_tag = imap_parser_read_word(client->parser);
		if (client->cmd_tag == NULL)
			return; /* need more data */
	}

	if (client->cmd_name == NULL) {
                client->cmd_name = imap_parser_read_word(client->parser);
		if (client->cmd_name == NULL)
			return; /* need more data */
	}

	switch (imap_parser_read_args(client->parser, 0, 0, &args)) {
	case -1:
		/* error */
		client_destroy(client, NULL);
		return;
	case -2:
		/* not enough data */
		return;
	}

	if (*client->cmd_tag == '\0' ||
	    !client_command_execute(client, client->cmd_name, args)) {
		client_send_tagline(client,
			"BAD Error in IMAP command received by server.");
	}

	client->cmd_finished = TRUE;
}

int client_read(struct client *client)
{
	switch (i_stream_read(client->input)) {
	case -2:
		/* buffer full */
		client_send_line(client, "* BYE Input buffer full, aborting");
		client_destroy(client, "Disconnected: Input buffer full");
		return FALSE;
	case -1:
		/* disconnected */
		client_destroy(client, "Disconnected");
		return FALSE;
	default:
		/* something was read */
		return TRUE;
	}
}

void client_input(void *context, int fd __attr_unused__,
		  struct io *io __attr_unused__)
{
	struct client *client = context;

	client->last_input = ioloop_time;

	if (!client_read(client))
		return;

	client_ref(client);

	o_stream_cork(client->output);
	client_handle_input(client);

	if (client_unref(client))
		o_stream_flush(client->output);
}

static void client_hash_destroy_oldest(void *key, void *value __attr_unused__,
				       void *context)
{
	struct client *client = key;
	struct client *const *destroy_clients;
	buffer_t *destroy_buf = context;
	size_t i, count;

	destroy_clients = buffer_get_data(destroy_buf, &count);
	count /= sizeof(struct client *);

	for (i = 0; i < count; i++) {
		if (destroy_clients[i]->created > client->created) {
			buffer_insert(destroy_buf, i * sizeof(struct client *),
				      &client, sizeof(struct client *));
			break;
		}
	}
}

static void client_destroy_oldest(void)
{
	struct client *const *destroy_clients;
	buffer_t *destroy_buf;
	size_t i, count;

	/* find the oldest clients and put them to destroy-buffer */
	destroy_buf = buffer_create_static_hard(data_stack_pool,
						sizeof(struct client *) *
						CLIENT_DESTROY_OLDEST_COUNT);
	hash_foreach(clients, client_hash_destroy_oldest, destroy_buf);

	/* then kill them */
	destroy_clients = buffer_get_data(destroy_buf, &count);
	count /= sizeof(struct client *);

	for (i = 0; i < count; i++) {
		client_destroy(destroy_clients[i],
			       "Disconnected: Connection queue full");
	}
}

struct client *client_create(int fd, struct ip_addr *ip, int imaps)
{
	struct client *client;

	if (max_logging_users > CLIENT_DESTROY_OLDEST_COUNT &&
	    hash_size(clients) >= max_logging_users) {
		/* reached max. users count, kill few of the
		   oldest connections */
		client_destroy_oldest();
	}

	/* always use nonblocking I/O */
	net_set_nonblock(fd, TRUE);

	client = i_new(struct client, 1);
	client->created = ioloop_time;
	client->refcount = 1;
	client->tls = imaps;

	memcpy(&client->ip, ip, sizeof(struct ip_addr));
	client->fd = fd;
	client->io = io_add(fd, IO_READ, client_input, client);
	client->input = i_stream_create_file(fd, default_pool, 8192, FALSE);
	client->output = o_stream_create_file(fd, default_pool, 1024,
					      IO_PRIORITY_DEFAULT, FALSE);
	client->parser = imap_parser_create(client->input, client->output,
					    MAX_INBUF_SIZE,
					    MAX_IMAP_ARG_ELEMENTS);
	client->plain_login = buffer_create_dynamic(system_pool, 128, 8192);

	client->last_input = ioloop_time;
	hash_insert(clients, client, client);

	main_ref();

	client_send_line(client, "* OK " PACKAGE " ready.");
	client_set_title(client);
	return client;
}

void client_destroy(struct client *client, const char *reason)
{
	if (reason != NULL)
		client_syslog(client, reason);

	hash_remove(clients, client);

	imap_parser_destroy(client->parser);
	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	net_disconnect(client->fd);
	client->fd = -1;

	client_unref(client);
}

void client_ref(struct client *client)
{
	client->refcount++;
}

int client_unref(struct client *client)
{
	if (--client->refcount > 0)
		return TRUE;

	i_stream_unref(client->input);
	o_stream_unref(client->output);

	buffer_free(client->plain_login);
	i_free(client);

	main_unref();
	return FALSE;
}

void client_send_line(struct client *client, const char *line)
{
	o_stream_send_str(client->output, line);
	o_stream_send(client->output, "\r\n", 2);
}

void client_send_tagline(struct client *client, const char *line)
{
	client_send_line(client, t_strconcat(client->cmd_tag, " ", line, NULL));
}

void client_syslog(struct client *client, const char *text)
{
	const char *host;

	host = net_ip2host(&client->ip);
	if (host == NULL)
		host = "??";

	i_info("%s [%s]", text, host);
}

static void client_hash_check_idle(void *key, void *value __attr_unused__,
				   void *context __attr_unused__)
{
	struct client *client = key;

	if (ioloop_time - client->last_input >= CLIENT_LOGIN_IDLE_TIMEOUT) {
		client_send_line(client, "* BYE Disconnected for inactivity.");
		client_destroy(client, "Disconnected: Inactivity");
	}
}

static void idle_timeout(void *context __attr_unused__,
			 struct timeout *timeout __attr_unused__)
{
	hash_foreach(clients, client_hash_check_idle, NULL);
}

unsigned int clients_get_count(void)
{
	return hash_size(clients);
}

static void client_hash_destroy(void *key, void *value __attr_unused__,
				void *context __attr_unused__)
{
	client_destroy(key, NULL);
}

void clients_destroy_all(void)
{
	hash_foreach(clients, client_hash_destroy, NULL);
}

void clients_init(void)
{
	clients = hash_create(default_pool, 128, NULL, NULL);
	to_idle = timeout_add(1000, idle_timeout, NULL);
}

void clients_deinit(void)
{
	clients_destroy_all();
	hash_destroy(clients);

	timeout_remove(to_idle);
}
