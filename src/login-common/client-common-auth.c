/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "safe-memset.h"
#include "login-proxy.h"
#include "auth-client.h"
#include "client-common.h"

#include <stdlib.h>

#define PROXY_FAILURE_MSG "Account is temporarily unavailable."
#define LOGIN_DNS_CLIENT_SOCKET_PATH "dns-client"

/* If we've been waiting auth server to respond for over this many milliseconds,
   send a "waiting" message. */
#define AUTH_WAITING_TIMEOUT_MSECS (30*1000)

#define CLIENT_AUTH_BUF_MAX_SIZE 8192

void client_auth_failed(struct client *client)
{
	i_free_and_null(client->master_data_prefix);

	if (client->auth_initializing || client->destroyed)
		return;

	if (client->io != NULL)
		io_remove(&client->io);

	client->io = io_add(client->fd, IO_READ, client_input, client);
	client_input(client);
}

static void client_auth_waiting_timeout(struct client *client)
{
	client_send_line(client, CLIENT_CMD_REPLY_STATUS,
			 client->master_tag == 0 ?
			 AUTH_SERVER_WAITING_MSG : AUTH_MASTER_WAITING_MSG);
	timeout_remove(&client->to_auth_waiting);
}

void client_set_auth_waiting(struct client *client)
{
	i_assert(client->to_auth_waiting == NULL);
	client->to_auth_waiting =
		timeout_add(AUTH_WAITING_TIMEOUT_MSECS,
			    client_auth_waiting_timeout, client);
}

static void client_auth_parse_args(struct client *client,
				   const char *const *args,
				   struct client_auth_reply *reply_r)
{
	const char *key, *value, *p;

	memset(reply_r, 0, sizeof(*reply_r));

	for (; *args != NULL; args++) {
		p = strchr(*args, '=');
		if (p == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, p);
			value = p + 1;
		}
		if (strcmp(key, "nologin") == 0)
			reply_r->nologin = TRUE;
		else if (strcmp(key, "proxy") == 0)
			reply_r->proxy = TRUE;
		else if (strcmp(key, "temp") == 0)
			reply_r->temp = TRUE;
		else if (strcmp(key, "authz") == 0)
			reply_r->authz_failure = TRUE;
		else if (strcmp(key, "reason") == 0)
			reply_r->reason = value;
		else if (strcmp(key, "host") == 0)
			reply_r->host = value;
		else if (strcmp(key, "port") == 0)
			reply_r->port = atoi(value);
		else if (strcmp(key, "destuser") == 0)
			reply_r->destuser = value;
		else if (strcmp(key, "pass") == 0)
			reply_r->password = value;
		else if (strcmp(key, "proxy_timeout") == 0)
			reply_r->proxy_timeout_msecs = 1000*atoi(value);
		else if (strcmp(key, "proxy_refresh") == 0)
			reply_r->proxy_refresh_secs = atoi(value);
		else if (strcmp(key, "master") == 0)
			reply_r->master_user = value;
		else if (strcmp(key, "ssl") == 0) {
			reply_r->ssl_flags |= PROXY_SSL_FLAG_YES;
			if (strcmp(value, "any-cert") == 0)
				reply_r->ssl_flags |= PROXY_SSL_FLAG_ANY_CERT;
			if (reply_r->port == 0)
				reply_r->port = login_binary.default_ssl_port;
		} else if (strcmp(key, "starttls") == 0) {
			reply_r->ssl_flags |= PROXY_SSL_FLAG_YES |
				PROXY_SSL_FLAG_STARTTLS;
			if (strcmp(value, "any-cert") == 0)
				reply_r->ssl_flags |= PROXY_SSL_FLAG_ANY_CERT;
		} else if (strcmp(key, "user") == 0) {
			/* already handled in login-common */
		} else if (client->set->auth_debug)
			i_debug("Ignoring unknown passdb extra field: %s", key);
	}
	if (reply_r->port == 0)
		reply_r->port = login_binary.default_port;

	if (reply_r->destuser == NULL)
		reply_r->destuser = client->virtual_user;
}

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

void client_proxy_finish_destroy_client(struct client *client)
{
	string_t *str = t_str_new(128);

	str_printfa(str, "proxy(%s): started proxying to %s:%u",
		    client->virtual_user,
		    login_proxy_get_host(client->login_proxy),
		    login_proxy_get_port(client->login_proxy));
	if (strcmp(client->virtual_user, client->proxy_user) != 0) {
		/* remote username is different, log it */
		str_append_c(str, '/');
		str_append(str, client->proxy_user);
	}
	if (client->proxy_master_user != NULL)
		str_printfa(str, " (master %s)", client->proxy_master_user);

	login_proxy_detach(client->login_proxy);
	client_destroy_success(client, str_c(str));
}

void client_proxy_log_failure(struct client *client, const char *line)
{
	string_t *str = t_str_new(128);

	str_printfa(str, "proxy(%s): Login failed to %s:%u",
		    client->virtual_user,
		    login_proxy_get_host(client->login_proxy),
		    login_proxy_get_port(client->login_proxy));
	if (strcmp(client->virtual_user, client->proxy_user) != 0) {
		/* remote username is different, log it */
		str_append_c(str, '/');
		str_append(str, client->proxy_user);
	}
	if (client->proxy_master_user != NULL)
		str_printfa(str, " (master %s)", client->proxy_master_user);
	str_append(str, ": ");
	str_append(str, line);
	i_info("%s", str_c(str));
}

void client_proxy_failed(struct client *client, bool send_line)
{
	if (send_line) {
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 PROXY_FAILURE_MSG);
	}

	login_proxy_free(&client->login_proxy);
	proxy_free_password(client);
	i_free_and_null(client->proxy_user);
	i_free_and_null(client->proxy_master_user);

	/* call this last - it may destroy the client */
	client_auth_failed(client);
}

static const char *get_disconnect_reason(struct istream *input)
{
	errno = input->stream_errno;
	return errno == 0 || errno == EPIPE ? "Connection closed" :
		t_strdup_printf("Connection closed: %m");
}

static void proxy_input(struct client *client)
{
	struct istream *input;
	const char *line;

	if (client->login_proxy == NULL) {
		/* we're just freeing the proxy */
		return;
	}

	input = login_proxy_get_istream(client->login_proxy);
	if (input == NULL) {
		if (client->destroyed) {
			/* we came here from client_destroy() */
			return;
		}

		/* failed for some reason, probably server disconnected */
		client_proxy_failed(client, TRUE);
		return;
	}

	i_assert(!client->destroyed);

	switch (i_stream_read(input)) {
	case -2:
		client_log_err(client, "proxy: Remote input buffer full");
		client_proxy_failed(client, TRUE);
		return;
	case -1:
		client_log_err(client, t_strdup_printf(
			"proxy: Remote %s:%u disconnected: %s (state=%u)",
			login_proxy_get_host(client->login_proxy),
			login_proxy_get_port(client->login_proxy),
			get_disconnect_reason(input), client->proxy_state));
		client_proxy_failed(client, TRUE);
		return;
	}

	while ((line = i_stream_next_line(input)) != NULL) {
		if (client->v.proxy_parse_line(client, line) != 0)
			break;
	}
}

static int proxy_start(struct client *client,
		       const struct client_auth_reply *reply)
{
	struct login_proxy_settings proxy_set;

	i_assert(reply->destuser != NULL);
	i_assert(!client->destroyed);

	client->v.proxy_reset(client);

	if (reply->password == NULL) {
		client_log_err(client, "proxy: password not given");
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 PROXY_FAILURE_MSG);
		return -1;
	}
	if (reply->host == NULL || *reply->host == '\0') {
		client_log_err(client, "proxy: host not given");
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 PROXY_FAILURE_MSG);
		return -1;
	}

	i_assert(client->refcount > 1);

	if (client->destroyed) {
		/* connection_queue_add() decided that we were the oldest
		   connection and killed us. */
		return -1;
	}
	if (login_proxy_is_ourself(client, reply->host, reply->port,
				   reply->destuser)) {
		client_log_err(client, "Proxying loops to itself");
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 PROXY_FAILURE_MSG);
		return -1;
	}

	memset(&proxy_set, 0, sizeof(proxy_set));
	proxy_set.host = reply->host;
	proxy_set.port = reply->port;
	proxy_set.dns_client_socket_path = LOGIN_DNS_CLIENT_SOCKET_PATH;
	proxy_set.connect_timeout_msecs = reply->proxy_timeout_msecs;
	proxy_set.notify_refresh_secs = reply->proxy_refresh_secs;
	proxy_set.ssl_flags = reply->ssl_flags;

	if (login_proxy_new(client, &proxy_set, proxy_input) < 0) {
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 PROXY_FAILURE_MSG);
		return -1;
	}

	client->proxy_user = i_strdup(reply->destuser);
	client->proxy_master_user = i_strdup(reply->master_user);
	client->proxy_password = i_strdup(reply->password);

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return 0;
}

static bool
client_auth_handle_reply(struct client *client,
			 const struct client_auth_reply *reply, bool success)
{
	if (reply->proxy) {
		/* we want to proxy the connection to another server.
		   don't do this unless authentication succeeded. with
		   master user proxying we can get FAIL with proxy still set.

		   proxy host=.. [port=..] [destuser=..] pass=.. */
		if (!success)
			return FALSE;
		if (proxy_start(client, reply) < 0)
			client_auth_failed(client);
		return TRUE;
	}
	return client->v.auth_handle_reply(client, reply);
}

static int client_auth_read_line(struct client *client)
{
	const unsigned char *data;
	size_t i, size;
	unsigned int len;

	if (i_stream_read_data(client->input, &data, &size, 0) == -1) {
		client_destroy(client, "Disconnected");
		return -1;
	}

	/* see if we have a full line */
	for (i = 0; i < size; i++) {
		if (data[i] == '\n')
			break;
	}
	if (str_len(client->auth_response) + i > CLIENT_AUTH_BUF_MAX_SIZE) {
		client_destroy(client, "Authentication response too large");
		return -1;
	}
	str_append_n(client->auth_response, data, i);
	i_stream_skip(client->input, i == size ? size : i+1);

	/* drop trailing \r */
	len = str_len(client->auth_response);
	if (len > 0 && str_c(client->auth_response)[len-1] == '\r')
		str_truncate(client->auth_response, len-1);

	return i < size;
}

int client_auth_parse_response(struct client *client)
{
	int ret;

	if ((ret = client_auth_read_line(client)) <= 0)
		return ret;

	if (strcmp(str_c(client->auth_response), "*") == 0) {
		sasl_server_auth_abort(client);
		return -1;
	}
	return 1;
}

static void client_auth_input(struct client *client)
{
	if (client->v.auth_parse_response(client) <= 0)
		return;

	client_set_auth_waiting(client);
	auth_client_request_continue(client->auth_request,
				     str_c(client->auth_response));
	io_remove(&client->io);

	memset(str_c_modifiable(client->auth_response), 0,
	       str_len(client->auth_response));
}

void client_auth_send_challenge(struct client *client, const char *data)
{
	struct const_iovec iov[3];

	iov[0].iov_base = "+ ";
	iov[0].iov_len = 2;
	iov[1].iov_base = data;
	iov[1].iov_len = strlen(data);
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	(void)o_stream_sendv(client->output, iov, 3);
}

static void
sasl_callback(struct client *client, enum sasl_server_reply sasl_reply,
	      const char *data, const char *const *args)
{
	struct client_auth_reply reply;

	i_assert(!client->destroyed ||
		 sasl_reply == SASL_SERVER_REPLY_AUTH_ABORTED ||
		 sasl_reply == SASL_SERVER_REPLY_MASTER_FAILED);

	switch (sasl_reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			client_auth_parse_args(client, args, &reply);
			if (client_auth_handle_reply(client, &reply, TRUE))
				break;
		}
		client_destroy_success(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_AUTH_ABORTED:
		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			client_auth_parse_args(client, args, &reply);
			reply.nologin = TRUE;
			if (client_auth_handle_reply(client, &reply, FALSE))
				break;
		}

		if (sasl_reply == SASL_SERVER_REPLY_AUTH_ABORTED) {
			client_send_line(client, CLIENT_CMD_REPLY_BAD,
					 "Authentication aborted by client.");
		} else if (data == NULL) {
			client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAILED,
					 AUTH_FAILED_MSG);
		} else {
			client_send_line(client,
					 CLIENT_CMD_REPLY_AUTH_FAIL_REASON,
					 data);
		}

		if (!client->destroyed)
			client_auth_failed(client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		if (data != NULL) {
			/* authentication itself succeeded, we just hit some
			   internal failure. */
			client_send_line(client,
					 CLIENT_CMD_REPLY_AUTH_FAIL_TEMP, data);
		}

		/* the fd may still be hanging somewhere in kernel or another
		   process. make sure the client gets disconnected. */
		if (shutdown(client->fd, SHUT_RDWR) < 0 && errno != ENOTCONN)
			i_error("shutdown() failed: %m");

		if (data == NULL)
			client_destroy_internal_failure(client);
		else
			client_destroy_success(client, data);
		break;
	case SASL_SERVER_REPLY_CONTINUE:
		client->v.auth_send_challenge(client, data);

		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);

		str_truncate(client->auth_response, 0);

		i_assert(client->io == NULL);
		client->io = io_add(client->fd, IO_READ,
				    client_auth_input, client);
		client_auth_input(client);
		return;
	}

	client_unref(&client);
}

int client_auth_begin(struct client *client, const char *mech_name,
		      const char *init_resp)
{
	if (!client->secured && strcmp(client->set->ssl, "required") == 0) {
		if (client->set->verbose_auth) {
			client_log(client, "Login failed: "
				   "SSL required for authentication");
		}
		client->auth_attempts++;
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_NOSSL,
			"Authentication not allowed until SSL/TLS is enabled.");
		return 1;
	}


	if (client->auth_response == NULL)
		client->auth_response = str_new(default_pool, 256);

	client_ref(client);
	client->auth_initializing = TRUE;
	sasl_server_auth_begin(client, login_binary.protocol, mech_name,
			       init_resp, sasl_callback);
	client->auth_initializing = FALSE;
	if (!client->authenticating)
		return 1;

	/* don't handle input until we get the initial auth reply */
	if (client->io != NULL)
		io_remove(&client->io);
	client_set_auth_waiting(client);
	return 0;
}

bool client_check_plaintext_auth(struct client *client, bool pass_sent)
{
	if (client->secured || !client->set->disable_plaintext_auth)
		return TRUE;

	if (client->set->verbose_auth) {
		client_log(client, "Login failed: "
			   "Plaintext authentication disabled");
	}
	if (pass_sent) {
		client_send_line(client, CLIENT_CMD_REPLY_STATUS_BAD,
			 "Plaintext authentication not allowed "
			 "without SSL/TLS, but your client did it anyway. "
			 "If anyone was listening, the password was exposed.");
	}
	client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_NOSSL,
			 AUTH_PLAINTEXT_DISABLED_MSG);
	client->auth_tried_disabled_plaintext = TRUE;
	client->auth_attempts++;
	return FALSE;
}

void clients_notify_auth_connected(void)
{
	struct client *client, *next;

	for (client = clients; client != NULL; client = next) {
		next = client->next;

		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (!client->greeting_sent)
			client->v.send_greeting(client);
		if (client->input_blocked) {
			client->input_blocked = FALSE;
			client_input(client);
		}
	}
}
