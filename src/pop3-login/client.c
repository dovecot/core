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
#include "client.h"
#include "client-authenticate.h"
#include "ssl-proxy.h"

/* max. length of input command line (spec says 512) */
#define MAX_INBUF_SIZE 2048

/* Disconnect client after idling this many seconds */
#define CLIENT_LOGIN_IDLE_TIMEOUT 60

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 10

/* When max. number of simultaneous connections is reached, few of the
   oldest connections are disconnected. Since we have to go through the whole
   client hash, it's faster if we disconnect multiple clients. */
#define CLIENT_DESTROY_OLDEST_COUNT 16

#if CLIENT_LOGIN_IDLE_TIMEOUT >= AUTH_REQUEST_TIMEOUT
#  error client idle timeout must be smaller than authentication timeout
#endif

static struct hash_table *clients;
static struct timeout *to_idle;

static void client_set_title(struct pop3_client *client)
{
	const char *host;

	if (!verbose_proctitle || !process_per_connection)
		return;

	host = net_ip2host(&client->common.ip);
	if (host == NULL)
		host = "??";

	process_title_set(t_strdup_printf(client->tls ? "[%s TLS]" : "[%s]",
					  host));
}

static void client_open_streams(struct pop3_client *client, int fd)
{
	client->input = i_stream_create_file(fd, default_pool, 8192, FALSE);
	client->output = o_stream_create_file(fd, default_pool, 1024,
					      IO_PRIORITY_DEFAULT, FALSE);
}

static int cmd_stls(struct pop3_client *client)
{
	int fd_ssl;

	if (client->tls) {
		client_send_line(client, "-ERR TLS is already active.");
		return TRUE;
	}

	if (!ssl_initialized) {
		client_send_line(client, "-ERR TLS support isn't enabled.");
		return TRUE;
	}

	client_send_line(client, "+OK Begin TLS negotiation now.");
	o_stream_flush(client->output);

	/* must be removed before ssl_proxy_new(), since it may
	   io_add() the same fd. */
	if (client->common.io != NULL) {
		io_remove(client->common.io);
		client->common.io = NULL;
	}

	fd_ssl = ssl_proxy_new(client->common.fd);
	if (fd_ssl != -1) {
		client->tls = TRUE;
                client_set_title(client);

		client->common.fd = fd_ssl;

		i_stream_unref(client->input);
		o_stream_unref(client->output);

		client_open_streams(client, fd_ssl);
		client->common.io = io_add(client->common.fd, IO_READ,
					   client_input, client);
	} else {
		client_send_line(client, "-ERR TLS initialization failed.");
		client_destroy(client, "TLS initialization failed.");
	}

	return TRUE;
}

static int cmd_quit(struct pop3_client *client)
{
	client_send_line(client, "+OK Logging out");
	client_destroy(client, "Aborted login");
	return TRUE;
}

static int client_command_execute(struct pop3_client *client, const char *cmd,
				  const char *args)
{
	cmd = str_ucase(t_strdup_noconst(cmd));
	if (strcmp(cmd, "CAPA") == 0)
		return cmd_capa(client, args);
	if (strcmp(cmd, "USER") == 0)
		return cmd_user(client, args);
	if (strcmp(cmd, "PASS") == 0)
		return cmd_pass(client, args);
	if (strcmp(cmd, "AUTH") == 0)
		return cmd_auth(client, args);
	if (strcmp(cmd, "STLS") == 0)
		return cmd_stls(client);
	if (strcmp(cmd, "QUIT") == 0)
		return cmd_quit(client);

	client_send_line(client, "-ERR Unknown command.");
	return FALSE;
}

int client_read(struct pop3_client *client)
{
	switch (i_stream_read(client->input)) {
	case -2:
		/* buffer full */
		client_send_line(client, "-ERR Input line too long, aborting");
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

void client_input(void *context)
{
	struct pop3_client *client = context;
	char *line, *args;

	client->last_input = ioloop_time;

	if (!client_read(client))
		return;

	client_ref(client);

	o_stream_cork(client->output);
	while (!client->output->closed &&
	       (line = i_stream_next_line(client->input)) != NULL) {
		args = strchr(line, ' ');
		if (args == NULL)
			args = "";
		else
			*args++ = '\0';

		if (client_command_execute(client, line, args))
			client->bad_counter = 0;
		else if (++client->bad_counter > CLIENT_MAX_BAD_COMMANDS) {
			client_send_line(client, "-ERR Too many bad commands.");
			client_destroy(client,
				       "Disconnected: Too many bad commands");
		}
	}

	if (client_unref(client))
		o_stream_flush(client->output);
}

static void client_hash_destroy_oldest(void *key, void *value __attr_unused__,
				       void *context)
{
	struct pop3_client *client = key;
	struct pop3_client *const *destroy_clients;
	buffer_t *destroy_buf = context;
	size_t i, count;

	destroy_clients = buffer_get_data(destroy_buf, &count);
	count /= sizeof(struct pop3_client *);

	for (i = 0; i < count; i++) {
		if (destroy_clients[i]->created > client->created) {
			buffer_insert(destroy_buf,
				      i * sizeof(struct pop3_client *),
				      &client, sizeof(struct pop3_client *));
			break;
		}
	}
}

static void client_destroy_oldest(void)
{
	struct pop3_client *const *destroy_clients;
	buffer_t *destroy_buf;
	size_t i, count;

	/* find the oldest clients and put them to destroy-buffer */
	destroy_buf = buffer_create_static_hard(data_stack_pool,
						sizeof(struct pop3_client *) *
						CLIENT_DESTROY_OLDEST_COUNT);
	hash_foreach(clients, client_hash_destroy_oldest, destroy_buf);

	/* then kill them */
	destroy_clients = buffer_get_data(destroy_buf, &count);
	count /= sizeof(struct pop3_client *);

	for (i = 0; i < count; i++) {
		client_destroy(destroy_clients[i],
			       "Disconnected: Connection queue full");
	}
}

struct client *client_create(int fd, struct ip_addr *ip, int ssl)
{
	struct pop3_client *client;

	if (max_logging_users > CLIENT_DESTROY_OLDEST_COUNT &&
	    hash_size(clients) >= max_logging_users) {
		/* reached max. users count, kill few of the
		   oldest connections */
		client_destroy_oldest();
	}

	/* always use nonblocking I/O */
	net_set_nonblock(fd, TRUE);

	client = i_new(struct pop3_client, 1);
	client->created = ioloop_time;
	client->refcount = 1;
	client->tls = ssl;

	client->common.ip = *ip;
	client->common.fd = fd;
	client->common.io = io_add(fd, IO_READ, client_input, client);
	client_open_streams(client, fd);
	client->plain_login = buffer_create_dynamic(system_pool, 128, 8192);

	client->last_input = ioloop_time;
	hash_insert(clients, client, client);

	main_ref();

	client_send_line(client, "+OK " PACKAGE " ready.");
	client_set_title(client);
	return &client->common;
}

void client_destroy(struct pop3_client *client, const char *reason)
{
	if (reason != NULL)
		client_syslog(client, reason);

	hash_remove(clients, client);

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->common.io != NULL) {
		io_remove(client->common.io);
		client->common.io = NULL;
	}

	net_disconnect(client->common.fd);
	client->common.fd = -1;

	i_free(client->common.virtual_user);
	client_unref(client);
}

void client_ref(struct pop3_client *client)
{
	client->refcount++;
}

int client_unref(struct pop3_client *client)
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

void client_send_line(struct pop3_client *client, const char *line)
{
	o_stream_send_str(client->output, line);
	o_stream_send(client->output, "\r\n", 2);
}

void client_syslog(struct pop3_client *client, const char *text)
{
	const char *host;

	host = net_ip2host(&client->common.ip);
	if (host == NULL)
		host = "??";

	i_info("%s [%s]", text, host);
}

static void client_hash_check_idle(void *key, void *value __attr_unused__,
				   void *context __attr_unused__)
{
	struct pop3_client *client = key;

	if (ioloop_time - client->last_input >= CLIENT_LOGIN_IDLE_TIMEOUT)
		client_destroy(client, "Disconnected: Inactivity");
}

static void idle_timeout(void *context __attr_unused__)
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
	clients = hash_create(default_pool, default_pool, 128, NULL, NULL);
	to_idle = timeout_add(1000, idle_timeout, NULL);
}

void clients_deinit(void)
{
	clients_destroy_all();
	hash_destroy(clients);

	timeout_remove(to_idle);
}
