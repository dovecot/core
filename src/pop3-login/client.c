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
#include "auth-client.h"
#include "ssl-proxy.h"
#include "hostpid.h"
#include "imem.h"

/* max. length of input command line (spec says 512), or max reply length in
   SASL authentication */
#define MAX_INBUF_SIZE 4096

/* max. size of output buffer. if it gets full, the client is disconnected.
   SASL authentication gives the largest output. */
#define MAX_OUTBUF_SIZE 4096

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
	const char *addr;

	if (!verbose_proctitle || !process_per_connection)
		return;

	addr = net_ip2addr(&client->common.ip);
	if (addr == NULL)
		addr = "??";

	process_title_set(t_strdup_printf(client->tls ? "[%s TLS]" : "[%s]",
					  addr));
}

static void client_open_streams(struct pop3_client *client, int fd)
{
	client->input = i_stream_create_file(fd, default_pool,
					     MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_file(fd, default_pool,
					      MAX_OUTBUF_SIZE, FALSE);
}

static void client_start_tls(struct pop3_client *client)
{
	int fd_ssl;

	fd_ssl = ssl_proxy_new(client->common.fd, &client->common.ip,
			       &client->common.proxy);
	if (fd_ssl == -1) {
		client_send_line(client, "-ERR TLS initialization failed.");
		client_destroy(client, "TLS initialization failed.");
		return;
	}

	client->tls = TRUE;
	client->secured = TRUE;
	client_set_title(client);

	client->common.fd = fd_ssl;

	i_stream_unref(client->input);
	o_stream_unref(client->output);

	client_open_streams(client, fd_ssl);
	client->common.io = io_add(client->common.fd, IO_READ,
				   client_input, client);
}

static void client_output_starttls(void *context)
{
	struct pop3_client *client = context;
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, "Disconnected");
		return;
	}

	if (ret > 0)
		client_start_tls(client);
}

static int cmd_stls(struct pop3_client *client)
{
	if (client->tls) {
		client_send_line(client, "-ERR TLS is already active.");
		return TRUE;
	}

	if (!ssl_initialized) {
		client_send_line(client, "-ERR TLS support isn't enabled.");
		return TRUE;
	}

	/* remove input handler, SSL proxy gives us a new fd. we also have to
	   remove it in case we have to wait for buffer to be flushed */
	if (client->common.io != NULL) {
		io_remove(client->common.io);
		client->common.io = NULL;
	}

	client_send_line(client, "+OK Begin TLS negotiation now.");
	if (o_stream_get_buffer_used_size(client->output) != 0) {
		/* the buffer has to be flushed */
		o_stream_set_flush_callback(client->output,
					    client_output_starttls, client);
	} else {
		client_start_tls(client);
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
	cmd = t_str_ucase(cmd);
	if (strcmp(cmd, "CAPA") == 0)
		return cmd_capa(client, args);
	if (strcmp(cmd, "USER") == 0)
		return cmd_user(client, args);
	if (strcmp(cmd, "PASS") == 0)
		return cmd_pass(client, args);
	if (strcmp(cmd, "AUTH") == 0)
		return cmd_auth(client, args);
	if (strcmp(cmd, "APOP") == 0)
		return cmd_apop(client, args);
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
		o_stream_uncork(client->output);
}

static void client_destroy_oldest(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	struct pop3_client *destroy_buf[CLIENT_DESTROY_OLDEST_COUNT];
	int i;

	/* find the oldest clients and put them to destroy-buffer */
	memset(destroy_buf, 0, sizeof(destroy_buf));

	iter = hash_iterate_init(clients);
	while (hash_iterate(iter, &key, &value)) {
		struct pop3_client *client = key;

		for (i = 0; i < CLIENT_DESTROY_OLDEST_COUNT; i++) {
			if (destroy_buf[i] == NULL ||
			    destroy_buf[i]->created > client->created) {
				/* @UNSAFE */
				memmove(destroy_buf+i+1, destroy_buf+i,
					sizeof(destroy_buf) -
					(i+1) * sizeof(struct pop3_client *));
				destroy_buf[i] = client;
				break;
			}
		}
	}
	hash_iterate_deinit(iter);

	/* then kill them */
	for (i = 0; i < CLIENT_DESTROY_OLDEST_COUNT; i++) {
		if (destroy_buf[i] == NULL)
			break;

		client_destroy(destroy_buf[i],
			       "Disconnected: Connection queue full");
	}
}

static char *get_apop_challenge(struct pop3_client *client)
{
	struct auth_connect_id *id = &client->auth_id;

	if (!auth_client_reserve_connection(auth_client, "APOP", id))
		return NULL;

	return i_strdup_printf("<%x.%x.%s@%s>", id->server_pid, id->connect_uid,
			       dec2str(ioloop_time), my_hostname);
}

static void client_auth_ready(struct pop3_client *client)
{
	client->common.io =
		io_add(client->common.fd, IO_READ, client_input, client);

	client->apop_challenge = get_apop_challenge(client);
	client_send_line(client, t_strconcat("+OK " PACKAGE " ready.",
					     client->apop_challenge, NULL));
}

struct client *client_create(int fd, int ssl, const struct ip_addr *local_ip,
			     const struct ip_addr *ip)
{
	struct pop3_client *client;
	const char *addr;

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

        addr = net_ip2addr(ip);
	client->secured = ssl ||
		(IPADDR_IS_V4(ip) && strncmp(addr, "127.", 4) == 0) ||
		(IPADDR_IS_V6(ip) && strcmp(addr, "::1") == 0);

	client->common.local_ip = *local_ip;
	client->common.ip = *ip;
	client->common.fd = fd;
	client_open_streams(client, fd);

	client->last_input = ioloop_time;
	hash_insert(clients, client, client);

	main_ref();

	client->auth_connected = auth_client_is_connected(auth_client);
	if (client->auth_connected)
		client_auth_ready(client);
	client_set_title(client);
	return &client->common;
}

void client_destroy(struct pop3_client *client, const char *reason)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	if (reason != NULL)
		client_syslog(client, reason);

	hash_remove(clients, client);

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->common.auth_request != NULL) {
		auth_client_request_abort(client->common.auth_request);
                client->common.auth_request = NULL;
	}

	if (client->common.master_tag != 0)
		master_request_abort(&client->common);

	if (client->common.io != NULL) {
		io_remove(client->common.io);
		client->common.io = NULL;
	}

	net_disconnect(client->common.fd);
	client->common.fd = -1;

	if (client->common.proxy != NULL)
		ssl_proxy_free(client->common.proxy);
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

	i_free(client->apop_challenge);
	i_free(client->common.virtual_user);
	i_free(client);

	main_unref();
	return FALSE;
}

void client_send_line(struct pop3_client *client, const char *line)
{
	struct const_iovec iov[2];
	ssize_t ret;

	iov[0].iov_base = line;
	iov[0].iov_len = strlen(line);
	iov[1].iov_base = "\r\n";
	iov[1].iov_len = 2;

	if ((ret = o_stream_sendv(client->output, iov, 2)) < 0)
		client_destroy(client, "Disconnected");
	else if ((size_t)ret != iov[0].iov_len + iov[1].iov_len)
		client_destroy(client, "Transmit buffer full");
}

void client_syslog(struct pop3_client *client, const char *text)
{
	const char *addr;

	addr = net_ip2addr(&client->common.ip);
	if (addr == NULL)
		addr = "??";

	i_info("%s [%s]", text, addr);
}

static void client_check_idle(struct pop3_client *client)
{
	if (ioloop_time - client->last_input >= CLIENT_LOGIN_IDLE_TIMEOUT)
		client_destroy(client, "Disconnected: Inactivity");
}

static void idle_timeout(void *context __attr_unused__)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(clients);
	while (hash_iterate(iter, &key, &value)) {
		struct pop3_client *client = key;

		client_check_idle(client);
	}
	hash_iterate_deinit(iter);
}

unsigned int clients_get_count(void)
{
	return hash_size(clients);
}

void clients_notify_auth_connected(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(clients);
	while (hash_iterate(iter, &key, &value)) {
		struct pop3_client *client = key;

		if (!client->auth_connected) {
			client->auth_connected = TRUE;
			client_auth_ready(client);
		}
	}
	hash_iterate_deinit(iter);
}

void clients_destroy_all(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(clients);
	while (hash_iterate(iter, &key, &value)) {
		struct pop3_client *client = key;

		client_destroy(client, NULL);
	}
	hash_iterate_deinit(iter);
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
