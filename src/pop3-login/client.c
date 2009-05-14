/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "randgen.h"
#include "process-title.h"
#include "safe-memset.h"
#include "strescape.h"
#include "master-service.h"
#include "master-auth.h"
#include "client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "pop3-proxy.h"
#include "hostpid.h"

/* max. size of output buffer. if it gets full, the client is disconnected.
   SASL authentication gives the largest output. */
#define MAX_OUTBUF_SIZE 4096

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 10

/* When max. number of simultaneous connections is reached, few of the
   oldest connections are disconnected. Since we have to go through all of the
   clients, it's faster if we disconnect multiple clients. */
#define CLIENT_DESTROY_OLDEST_COUNT 16

#if CLIENT_LOGIN_IDLE_TIMEOUT_MSECS >= AUTH_REQUEST_TIMEOUT*1000
#  error client idle timeout must be smaller than authentication timeout
#endif

const char *login_protocol = "pop3";
const char *login_process_name = "pop3-login";

static void client_set_title(struct pop3_client *client)
{
	const char *addr;

	if (!client->common.set->verbose_proctitle ||
	    !client->common.set->login_process_per_connection)
		return;

	addr = net_ip2addr(&client->common.ip);
	if (addr == NULL)
		addr = "??";

	process_title_set(t_strdup_printf(client->common.tls ?
					  "[%s TLS]" : "[%s]", addr));
}

static void client_open_streams(struct pop3_client *client, int fd)
{
	client->common.input =
		i_stream_create_fd(fd, LOGIN_MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
}

static void client_start_tls(struct pop3_client *client)
{
	int fd_ssl;

	client_ref(client);
	if (!client_unref(client) || client->destroyed)
		return;

	fd_ssl = ssl_proxy_new(client->common.fd, &client->common.ip,
			       client->common.set, &client->common.proxy);
	if (fd_ssl == -1) {
		client_send_line(client, "-ERR TLS initialization failed.");
		client_destroy(client,
			       "Disconnected: TLS initialization failed.");
		return;
	}

	client->common.proxying = TRUE;
	client->common.tls = TRUE;
	client->common.secured = TRUE;
	client_set_title(client);

	client->common.fd = fd_ssl;

	i_stream_unref(&client->common.input);
	o_stream_unref(&client->output);

	client_open_streams(client, fd_ssl);
	client->io = io_add(client->common.fd, IO_READ, client_input, client);
}

static int client_output_starttls(struct pop3_client *client)
{
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, "Disconnected");
		return 1;
	}

	if (ret > 0) {
		o_stream_unset_flush_callback(client->output);
		client_start_tls(client);
	}
	return 1;
}

static bool cmd_stls(struct pop3_client *client)
{
	if (client->common.tls) {
		client_send_line(client, "-ERR TLS is already active.");
		return TRUE;
	}

	if (!ssl_initialized) {
		client_send_line(client, "-ERR TLS support isn't enabled.");
		return TRUE;
	}

	/* remove input handler, SSL proxy gives us a new fd. we also have to
	   remove it in case we have to wait for buffer to be flushed */
	if (client->io != NULL)
		io_remove(&client->io);

	client_send_line(client, "+OK Begin TLS negotiation now.");

	/* uncork the old fd */
	o_stream_uncork(client->output);

	if (o_stream_flush(client->output) <= 0) {
		/* the buffer has to be flushed */
		o_stream_set_flush_pending(client->output, TRUE);
		o_stream_set_flush_callback(client->output,
					    client_output_starttls, client);
	} else {
		client_start_tls(client);
	}
	return TRUE;
}

static bool cmd_quit(struct pop3_client *client)
{
	client_send_line(client, "+OK Logging out");
	client_destroy(client, "Aborted login");
	return TRUE;
}

static bool client_command_execute(struct pop3_client *client, const char *cmd,
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

bool client_read(struct pop3_client *client)
{
	switch (i_stream_read(client->common.input)) {
	case -2:
		/* buffer full */
		client_send_line(client, "-ERR Input line too long, aborting");
		client_destroy(client, "Disconnected: Input buffer full");
		return FALSE;
	case -1:
		/* disconnected */
		client_destroy(client, "Disconnected");
		return FALSE;
	case 0:
		/* nothing new read */
		return TRUE;
	default:
		/* something was read */
		timeout_reset(client->to_idle_disconnect);
		return TRUE;
	}
}

void client_input(struct pop3_client *client)
{
	char *line, *args;

	i_assert(!client->common.authenticating);

	if (!client_read(client))
		return;

	client_ref(client);

	o_stream_cork(client->output);
	/* if a command starts an authentication, stop processing further
	   commands until the authentication is finished. */
	while (!client->output->closed && !client->common.authenticating &&
	       (line = i_stream_next_line(client->common.input)) != NULL) {
		args = strchr(line, ' ');
		if (args != NULL)
			*args++ = '\0';

		if (client_command_execute(client, line,
					   args != NULL ? args : ""))
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

void client_destroy_oldest(void)
{
	unsigned int max_connections =
		global_login_settings->login_max_connections;
	struct client *client;
	struct pop3_client *destroy_buf[CLIENT_DESTROY_OLDEST_COUNT];
	unsigned int i, destroy_count;

	/* find the oldest clients and put them to destroy-buffer */
	memset(destroy_buf, 0, sizeof(destroy_buf));

	destroy_count = max_connections > CLIENT_DESTROY_OLDEST_COUNT*2 ?
		CLIENT_DESTROY_OLDEST_COUNT : I_MIN(max_connections/2, 1);
	for (client = clients; client != NULL; client = client->next) {
		struct pop3_client *pop3_client = (struct pop3_client *)client;

		for (i = 0; i < destroy_count; i++) {
			if (destroy_buf[i] == NULL ||
			    destroy_buf[i]->created > pop3_client->created) {
				/* @UNSAFE */
				memmove(destroy_buf+i+1, destroy_buf+i,
					sizeof(destroy_buf) -
					(i+1) * sizeof(struct pop3_client *));
				destroy_buf[i] = pop3_client;
				break;
			}
		}
	}

	/* then kill them */
	for (i = 0; i < destroy_count; i++) {
		if (destroy_buf[i] == NULL)
			break;

		client_destroy(destroy_buf[i],
			       "Disconnected: Connection queue full");
	}
}

static char *get_apop_challenge(struct pop3_client *client)
{
	struct auth_connect_id *id = &client->auth_id;
	unsigned char buffer[16];
        buffer_t *buf;

	if (!auth_client_reserve_connection(auth_client, "APOP", id))
		return NULL;

	random_fill(buffer, sizeof(buffer));
	buf = buffer_create_static_hard(pool_datastack_create(),
			MAX_BASE64_ENCODED_SIZE(sizeof(buffer)) + 1);
	base64_encode(buffer, sizeof(buffer), buf);
	buffer_append_c(buf, '\0');

	return i_strdup_printf("<%x.%x.%lx.%s@%s>",
			       id->server_pid, id->connect_uid,
			       (unsigned long)ioloop_time,
			       (const char *)buf->data, my_hostname);
}

static void client_auth_ready(struct pop3_client *client)
{
	client->io = io_add(client->common.fd, IO_READ, client_input, client);

	client->apop_challenge = get_apop_challenge(client);
	client_send_line(client, t_strconcat("+OK ",
					     client->common.set->login_greeting,
					     client->apop_challenge != NULL ?
					     " " : NULL,
					     client->apop_challenge, NULL));
}

static void client_idle_disconnect_timeout(struct pop3_client *client)
{
	client_destroy(client, "Disconnected: Inactivity");
}

struct client *client_create(int fd, bool ssl, pool_t pool,
			     const struct login_settings *set,
			     const struct ip_addr *local_ip,
			     const struct ip_addr *remote_ip)
{
	struct pop3_client *client;

	i_assert(fd != -1);

	if (clients_get_count() >= set->login_max_connections) {
		/* reached max. users count, kill few of the
		   oldest connections */
		client_destroy_oldest();
	}

	/* always use nonblocking I/O */
	net_set_nonblock(fd, TRUE);

	client = p_new(pool, struct pop3_client, 1);
	client->created = ioloop_time;
	client->refcount = 1;

	client->common.pool = pool;
	client->common.set = set;
	client->common.local_ip = *local_ip;
	client->common.ip = *remote_ip;
	client->common.fd = fd;
	client->common.tls = ssl;
	client->common.trusted = client_is_trusted(&client->common);
	client->common.secured = ssl || client->common.trusted ||
		net_ip_compare(remote_ip, local_ip);

	client_open_streams(client, fd);
	client_link(&client->common);

	client->auth_connected = auth_client_is_connected(auth_client);
	if (client->auth_connected)
		client_auth_ready(client);
	client_set_title(client);

	client->to_idle_disconnect =
		timeout_add(CLIENT_LOGIN_IDLE_TIMEOUT_MSECS,
			    client_idle_disconnect_timeout, client);
	return &client->common;
}

void client_destroy_success(struct pop3_client *client, const char *reason)
{
	client->login_success = TRUE;
	client_destroy(client, reason);
}

void client_destroy(struct pop3_client *client, const char *reason)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	if (!client->login_success && reason != NULL) {
		reason = t_strconcat(reason, " ",
			client_get_extra_disconnect_reason(&client->common),
			NULL);
	}
	if (reason != NULL)
		client_syslog(&client->common, reason);

	client_unlink(&client->common);

	if (client->common.input != NULL)
		i_stream_close(client->common.input);
	if (client->output != NULL)
		o_stream_close(client->output);

	if (client->common.master_tag != 0) {
		i_assert(client->common.auth_request == NULL);
		i_assert(client->common.authenticating);
		master_auth_request_abort(service, client->common.master_tag);
	} else if (client->common.auth_request != NULL) {
		i_assert(client->common.authenticating);
		sasl_server_auth_client_error(&client->common, NULL);
	} else {
		i_assert(!client->common.authenticating);
	}

	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_idle_disconnect != NULL)
		timeout_remove(&client->to_idle_disconnect);
	if (client->to_authfail_delay != NULL)
		timeout_remove(&client->to_authfail_delay);

	if (client->common.fd != -1) {
		net_disconnect(client->common.fd);
		client->common.fd = -1;
	}

	if (client->proxy_password != NULL) {
		safe_memset(client->proxy_password, 0,
			    strlen(client->proxy_password));
		i_free(client->proxy_password);
		client->proxy_password = NULL;
	}

	i_free(client->proxy_user);
	client->proxy_user = NULL;

	if (client->proxy != NULL)
		login_proxy_free(&client->proxy);

	if (client->common.proxy != NULL) {
		ssl_proxy_free(client->common.proxy);
		client->common.proxy = NULL;
	}
	client_unref(client);
}

void client_destroy_internal_failure(struct pop3_client *client)
{
	client_send_line(client, "-ERR [IN-USE] Internal login failure. "
			 "Refer to server log for more information.");
	client_destroy(client, "Internal login failure");
}

void client_ref(struct pop3_client *client)
{
	client->refcount++;
}

bool client_unref(struct pop3_client *client)
{
	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	i_assert(client->destroyed);

	if (client->common.input != NULL)
		i_stream_unref(&client->common.input);
	if (client->output != NULL)
		o_stream_unref(&client->output);

	if (!client->common.proxying) {
		i_assert(client->common.proxy == NULL);
		master_service_client_connection_destroyed(service);
	}

	i_free(client->last_user);
	i_free(client->apop_challenge);
	i_free(client->common.virtual_user);
	i_free(client->common.auth_mech_name);
	i_free(client);
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

	ret = o_stream_sendv(client->output, iov, 2);
	if (ret < 0 || (size_t)ret != iov[0].iov_len + iov[1].iov_len) {
		/* either disconnection or buffer full. in either case we
		   want this connection destroyed. however destroying it here
		   might break things if client is still tried to be accessed
		   without being referenced.. */
		i_stream_close(client->common.input);
	}
}

void clients_notify_auth_connected(void)
{
	struct client *client;

	for (client = clients; client != NULL; client = client->next) {
		struct pop3_client *pop3_client = (struct pop3_client *)client;

		if (!pop3_client->auth_connected) {
			pop3_client->auth_connected = TRUE;
			client_auth_ready(pop3_client);
		}
	}
}

void clients_destroy_all(void)
{
	struct client *client, *next;

	for (client = clients; client != NULL; client = next) {
		struct pop3_client *pop3_client = (struct pop3_client *)client;

		next = client->next;
		client_destroy(pop3_client, "Disconnected: Shutting down");
	}
}

void clients_init(void)
{
    /* Nothing to initialize for POP3 */
}

void clients_deinit(void)
{
	clients_destroy_all();
}
