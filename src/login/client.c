/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "hash.h"
#include "iobuffer.h"
#include "client.h"
#include "client-authenticate.h"
#include "ssl-proxy.h"

#include <syslog.h>

/* Disconnect client after idling this many seconds */
#define CLIENT_LOGIN_IDLE_TIMEOUT 60

/* When max. number of simultaneous connections is reached, few of the
   oldest connections are disconnected. Since we have to go through the whole
   client hash, it's faster if we disconnect multiple clients. */
#define CLIENT_DESTROY_OLDEST_COUNT 16

static HashTable *clients;
static Timeout to_idle;

static int cmd_capability(Client *client)
{
	const char *capability;

	capability = t_strconcat("* CAPABILITY " CAPABILITY_STRING,
				 disable_plaintext_auth && !client->tls ?
				 " LOGINDISABLED" : "",
				 client_authenticate_get_capabilities(),
				 NULL);
	client_send_line(client, capability);
	client_send_tagline(client, "OK Capability completed.");
	return TRUE;
}

static int cmd_starttls(Client *client)
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
	io_buffer_send_flush(client->outbuf);

	fd_ssl = ssl_proxy_new(client->fd);
	if (fd_ssl != -1) {
		client->tls = TRUE;
		client->fd = fd_ssl;
		client->inbuf->fd = fd_ssl;
		client->outbuf->fd = fd_ssl;
	} else {
		client_send_line(client, " * BYE TLS handehake failed.");
		client_destroy(client, "TLS handshake failed");
	}

	return TRUE;
}

static int cmd_noop(Client *client)
{
	client_send_tagline(client, "OK NOOP completed.");
	return TRUE;
}

static int cmd_logout(Client *client)
{
	client_send_line(client, "* BYE Logging out");
	client_send_tagline(client, "OK Logout completed.");
	client_destroy(client, "Logged out");
	return TRUE;
}

int client_read(Client *client)
{
	switch (io_buffer_read(client->inbuf)) {
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

static char *get_next_arg(char **line)
{
	char *start;
	int quoted;

	while (**line == ' ') (*line)++;

	if (**line == '"') {
		quoted = TRUE;
		(*line)++;

		start = *line;
		while (**line != '\0' && **line != '"') {
			if (**line == '\\' && (*line)[1] != '\0')
				(*line)++;
			(*line)++;
		}

		if (**line == '"')
			*(*line)++ = '\0';
		string_remove_escapes(start);
	} else {
		start = *line;
		while (**line != '\0' && **line != ' ')
			(*line)++;

		if (**line == ' ')
			*(*line)++ = '\0';
	}

	return start;
}

static int client_command_execute(Client *client, char *line)
{
	char *cmd;

	cmd = get_next_arg(&line);
	str_ucase(cmd);

	if (strcmp(cmd, "LOGIN") == 0) {
		char *user, *pass;

		user = get_next_arg(&line);
		pass = get_next_arg(&line);
		return cmd_login(client, user, pass);
	}
	if (strcmp(cmd, "AUTHENTICATE") == 0)
		return cmd_authenticate(client, get_next_arg(&line));
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

void client_input(void *context, int fd __attr_unused__,
		  IO io __attr_unused__)
{
	Client *client = context;
	char *line;

	client->last_input = ioloop_time;

	i_free(client->tag);
	client->tag = i_strdup("*");

	if (!client_read(client))
		return;

	client_ref(client);
	io_buffer_cork(client->outbuf);

	while ((line = io_buffer_next_line(client->inbuf)) != NULL) {
		/* split the arguments, make sure we have at
		   least tag + command */
		i_free(client->tag);
		client->tag = i_strdup(get_next_arg(&line));

		if (*client->tag == '\0' ||
		    !client_command_execute(client, line)) {
			/* error */
			client_send_tagline(client, "BAD Error in IMAP command "
					    "received by server.");
		}
	}

	if (client_unref(client))
		io_buffer_send_flush(client->outbuf);
}

static void client_hash_destroy_oldest(void *key, void *value __attr_unused__,
				       void *context)
{
	Client *client = key;
	Client **destroy_clients = context;
	int i;

	for (i = 0; i < CLIENT_DESTROY_OLDEST_COUNT; i++) {
		if (destroy_clients[i] == NULL ||
		    destroy_clients[i]->created > client->created) {
			memmove(destroy_clients+i+1, destroy_clients+i,
				sizeof(Client *) *
				(CLIENT_DESTROY_OLDEST_COUNT - i-1));
			destroy_clients[i] = client;
			break;
		}
	}
}

static void client_destroy_oldest(void)
{
	Client *destroy_clients[CLIENT_DESTROY_OLDEST_COUNT];
	int i;

	memset(destroy_clients, 0, sizeof(destroy_clients));
	hash_foreach(clients, client_hash_destroy_oldest, destroy_clients);

	for (i = 0; i < CLIENT_DESTROY_OLDEST_COUNT; i++) {
		client_destroy(destroy_clients[i],
			       "Disconnected: Connection queue full");
	}
}

Client *client_create(int fd, IPADDR *ip)
{
	Client *client;

	if (max_logging_users > CLIENT_DESTROY_OLDEST_COUNT &&
	    hash_size(clients) >= max_logging_users) {
		/* reached max. users count, kill few of the
		   oldest connections */
		client_destroy_oldest();
	}

	/* always use nonblocking I/O */
	net_set_nonblock(fd, TRUE);

	client = i_new(Client, 1);
	client->created = ioloop_time;
	client->refcount = 1;

	memcpy(&client->ip, ip, sizeof(IPADDR));
	client->fd = fd;
	client->io = io_add(fd, IO_READ, client_input, client);
	client->inbuf = io_buffer_create(fd, default_pool,
					 IO_PRIORITY_DEFAULT, 8192);
	client->outbuf = io_buffer_create(fd, default_pool,
					  IO_PRIORITY_DEFAULT, 1024);
        client->last_input = ioloop_time;
	hash_insert(clients, client, client);

	client_send_line(client, "* OK " PACKAGE " ready.");
	return client;
}

void client_destroy(Client *client, const char *reason)
{
	if (reason != NULL)
		client_syslog(client, reason);

	hash_remove(clients, client);

	io_buffer_close(client->inbuf);
	io_buffer_close(client->outbuf);

	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	net_disconnect(client->fd);
	client->fd = -1;

	client_unref(client);
}

void client_ref(Client *client)
{
	client->refcount++;
}

int client_unref(Client *client)
{
	if (--client->refcount > 0)
		return TRUE;

	io_buffer_unref(client->inbuf);
	io_buffer_unref(client->outbuf);

	i_free(client->tag);
	i_free(client->plain_login);
	i_free(client);
	return FALSE;
}

void client_send_line(Client *client, const char *line)
{
	io_buffer_send(client->outbuf, line, strlen(line));
	io_buffer_send(client->outbuf, "\r\n", 2);
}

void client_send_tagline(Client *client, const char *line)
{
	client_send_line(client, t_strconcat(client->tag, " ", line, NULL));
}

void client_syslog(Client *client, const char *text)
{
	char host[MAX_IP_LEN];

	if (net_ip2host(&client->ip, host) == -1)
		host[0] = '\0';

	syslog(LOG_INFO, "%s [%s]", text, host);
}

static void client_hash_check_idle(void *key, void *value __attr_unused__,
				   void *context __attr_unused__)
{
	Client *client = key;

	if (ioloop_time - client->last_input >= CLIENT_LOGIN_IDLE_TIMEOUT) {
		client_send_line(client, "* BYE Disconnected for inactivity.");
		client_destroy(client, "Disconnected: Inactivity");
	}
}

static void idle_timeout(void *context __attr_unused__,
			 Timeout timeout __attr_unused__)
{
	hash_foreach(clients, client_hash_check_idle, NULL);
}

void clients_init(void)
{
	clients = hash_create(default_pool, 128, NULL, NULL);
	to_idle = timeout_add(1000, idle_timeout, NULL);
}

static void client_hash_destroy(void *key, void *value __attr_unused__,
				void *context __attr_unused__)
{
	client_destroy(key, NULL);
}

void clients_deinit(void)
{
	hash_foreach(clients, client_hash_destroy, NULL);
	hash_destroy(clients);

	timeout_remove(to_idle);
}
