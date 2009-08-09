/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-resp-code.h"
#include "imap-parser.h"
#include "auth-client.h"
#include "client.h"
#include "client-authenticate.h"
#include "imap-proxy.h"

#include <stdlib.h>

#define AUTH_FAILURE_DELAY_INCREASE_MSECS 5000

#define IMAP_SERVICE_NAME "imap"

const char *client_authenticate_get_capabilities(struct imap_client *client)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	mech = sasl_server_get_advertised_mechs(&client->common, &count);
	for (i = 0; i < count; i++) {
		str_append_c(str, ' ');
		str_append(str, "AUTH=");
		str_append(str, mech[i].name);
	}

	return str_c(str);
}

static void client_auth_input(struct imap_client *client)
{
	char *line;

	if (!client_read(client))
		return;

	if (client->skip_line) {
		if (i_stream_next_line(client->common.input) == NULL)
			return;

		client->skip_line = FALSE;
	}

	/* @UNSAFE */
	line = i_stream_next_line(client->common.input);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0)
		sasl_server_auth_abort(&client->common);
	else {
		client_set_auth_waiting(client);
		auth_client_request_continue(client->common.auth_request, line);
		io_remove(&client->io);

		/* clear sensitive data */
		safe_memset(line, 0, strlen(line));
	}
}

static void client_authfail_delay_timeout(struct imap_client *client)
{
	timeout_remove(&client->to_authfail_delay);

	/* get back to normal client input. */
	i_assert(client->io == NULL);
	client->io = io_add(client->common.fd, IO_READ, client_input, client);
	client_input(client);
}

void client_auth_failed(struct imap_client *client, bool nodelay)
{
	unsigned int delay_msecs;

	i_free_and_null(client->common.master_data_prefix);

	if (client->auth_initializing)
		return;

	if (client->io != NULL)
		io_remove(&client->io);
	if (nodelay) {
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);
		client_input(client);
		return;
	}

	/* increase the timeout after each unsuccessful attempt, but don't
	   increase it so high that the idle timeout would be triggered */
	delay_msecs = client->common.auth_attempts *
		AUTH_FAILURE_DELAY_INCREASE_MSECS;
	if (delay_msecs > CLIENT_LOGIN_IDLE_TIMEOUT_MSECS)
		delay_msecs = CLIENT_LOGIN_IDLE_TIMEOUT_MSECS - 1000;

	i_assert(client->to_authfail_delay == NULL);
	client->to_authfail_delay =
		timeout_add(delay_msecs, client_authfail_delay_timeout, client);
}

static bool client_handle_args(struct imap_client *client,
			       const char *const *args, bool success,
			       bool *nodelay_r)
{
	const char *reason = NULL, *host = NULL, *destuser = NULL, *pass = NULL;
	const char *master_user = NULL;
	const char *key, *value, *p;
	enum login_proxy_ssl_flags ssl_flags = 0;
	string_t *reply;
	unsigned int port = 143;
	bool proxy = FALSE, temp = FALSE, nologin = !success;
	bool authz_failure = FALSE;

	*nodelay_r = FALSE;
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
			nologin = TRUE;
		else if (strcmp(key, "nodelay") == 0)
			*nodelay_r = TRUE;
		else if (strcmp(key, "proxy") == 0)
			proxy = TRUE;
		else if (strcmp(key, "temp") == 0)
			temp = TRUE;
		else if (strcmp(key, "authz") == 0)
			authz_failure = TRUE;
		else if (strcmp(key, "reason") == 0)
			reason = value;
		else if (strcmp(key, "host") == 0)
			host = value;
		else if (strcmp(key, "port") == 0)
			port = atoi(value);
		else if (strcmp(key, "destuser") == 0)
			destuser = value;
		else if (strcmp(key, "pass") == 0)
			pass = value;
		else if (strcmp(key, "master") == 0)
			master_user = value;
		else if (strcmp(key, "user") == 0) {
			/* already handled in login-common */
		} else if (client->common.set->auth_debug)
			i_info("Ignoring unknown passdb extra field: %s", key);
	}

	if (destuser == NULL)
		destuser = client->common.virtual_user;

	if (proxy) {
		/* we want to proxy the connection to another server.
		   don't do this unless authentication succeeded. with
		   master user proxying we can get FAIL with proxy still set.

		   proxy host=.. [port=..] [destuser=..] pass=.. */
		if (!success)
			return FALSE;
		if (imap_proxy_new(client, host, port, destuser, master_user,
				   pass, ssl_flags) < 0)
			client_auth_failed(client, TRUE);
		return TRUE;
	}

	if (host != NULL) {
		/* IMAP referral

		   [nologin] referral host=.. [port=..] [destuser=..]
		   [reason=..]

		   NO [REFERRAL imap://destuser;AUTH=..@host:port/] Can't login.
		   OK [...] Logged in, but you should use this server instead.
		   .. [REFERRAL ..] (Reason from auth server)
		*/
		reply = t_str_new(128);
		str_append(reply, nologin ? "NO " : "OK ");
		str_printfa(reply, "[REFERRAL imap://%s;AUTH=%s@%s",
			    destuser, client->common.auth_mech_name, host);
		if (port != 143)
			str_printfa(reply, ":%u", port);
		str_append(reply, "/] ");
		if (reason != NULL)
			str_append(reply, reason);
		else if (nologin)
			str_append(reply, "Try this server instead.");
		else {
			str_append(reply, "Logged in, but you should use "
				   "this server instead.");
		}
		client_send_tagline(client, str_c(reply));
		if (!nologin) {
			client_destroy_success(client, "Login with referral");
			return TRUE;
		}
	} else if (nologin) {
		/* Authentication went ok, but for some reason user isn't
		   allowed to log in. Shouldn't probably happen. */
		reply = t_str_new(128);
		if (reason != NULL)
			str_printfa(reply, "NO [ALERT] %s", reason);
		else if (temp) {
			str_append(reply, "NO ["IMAP_RESP_CODE_UNAVAILABLE"] "
				   AUTH_TEMP_FAILED_MSG);
		} else if (authz_failure) {
			str_append(reply, "NO "IMAP_AUTHZ_FAILED_MSG);
		} else {
			str_append(reply, "NO "IMAP_AUTH_FAILED_MSG);
		}
		client_send_tagline(client, str_c(reply));
	} else {
		/* normal login/failure */
		return FALSE;
	}

	i_assert(nologin);

	if (!client->destroyed)
		client_auth_failed(client, *nodelay_r);
	return TRUE;
}

static void sasl_callback(struct client *_client, enum sasl_server_reply reply,
			  const char *data, const char *const *args)
{
	struct imap_client *client = (struct imap_client *)_client;
	struct const_iovec iov[3];
	const char *msg;
	size_t data_len;
	bool nodelay;

	i_assert(!client->destroyed ||
		 reply == SASL_SERVER_REPLY_AUTH_ABORTED ||
		 reply == SASL_SERVER_REPLY_MASTER_FAILED);

	switch (reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			if (client_handle_args(client, args, TRUE, &nodelay))
				break;
		}
		client_destroy_success(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_AUTH_ABORTED:
		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			if (client_handle_args(client, args, FALSE, &nodelay))
				break;
		}

		if (reply == SASL_SERVER_REPLY_AUTH_ABORTED)
			msg = "BAD Authentication aborted by client.";
		else if (data == NULL)
			msg = "NO "IMAP_AUTH_FAILED_MSG;
		else
			msg = t_strconcat("NO [ALERT] ", data, NULL);
		client_send_tagline(client, msg);

		if (!client->destroyed)
			client_auth_failed(client, nodelay);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		if (data == NULL)
			client_destroy_internal_failure(client);
		else {
			client_send_tagline(client,
					    t_strconcat("NO ", data, NULL));
			/* authentication itself succeeded, we just hit some
			   internal failure. */
			client_destroy_success(client, data);
		}
		break;
	case SASL_SERVER_REPLY_CONTINUE:
		data_len = strlen(data);
		iov[0].iov_base = "+ ";
		iov[0].iov_len = 2;
		iov[1].iov_base = data;
		iov[1].iov_len = data_len;
		iov[2].iov_base = "\r\n";
		iov[2].iov_len = 2;

		/* don't check return value here. it gets tricky if we try
		   to call client_destroy() in here. */
		(void)o_stream_sendv(client->output, iov, 3);

		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);

		i_assert(client->io == NULL);
		client->io = io_add(client->common.fd, IO_READ,
				    client_auth_input, client);
		client_auth_input(client);
		return;
	}

	client_unref(client);
}

static int client_auth_begin(struct imap_client *client, const char *mech_name,
			     const char *init_resp)
{
	char *prefix;

	prefix = i_strdup_printf("%d%s",
				 client->client_ignores_capability_resp_code,
				 client->cmd_tag);

	i_free(client->common.master_data_prefix);
	client->common.master_data_prefix = (void *)prefix;
	client->common.master_data_prefix_len = strlen(prefix)+1;

	client_ref(client);
	client->auth_initializing = TRUE;
	sasl_server_auth_begin(&client->common, IMAP_SERVICE_NAME, mech_name,
			       init_resp, sasl_callback);
	client->auth_initializing = FALSE;
	if (!client->common.authenticating)
		return 1;

	/* don't handle input until we get the initial auth reply */
	if (client->io != NULL)
		io_remove(&client->io);
	client_set_auth_waiting(client);
	return 0;
}

int cmd_authenticate(struct imap_client *client, const struct imap_arg *args)
{
	const char *mech_name, *init_resp = NULL;

	/* we want only one argument: authentication mechanism name */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return -1;
	if (args[1].type != IMAP_ARG_EOL) {
		/* optional SASL initial response */
		if (args[1].type != IMAP_ARG_ATOM ||
		    args[2].type != IMAP_ARG_EOL)
			return -1;
		init_resp = IMAP_ARG_STR(&args[1]);
	}

	if (!client->common.secured &&
	    strcmp(client->common.set->ssl, "required") == 0) {
		if (client->common.set->verbose_auth) {
			client_syslog(&client->common, "Login failed: "
				      "SSL required for authentication");
		}
		client->common.auth_attempts++;
		client_send_tagline(client,
			"NO ["IMAP_RESP_CODE_PRIVACYREQUIRED"] "
			"Authentication not allowed until SSL/TLS is enabled.");
		return 1;
	}

	mech_name = IMAP_ARG_STR(&args[0]);
	if (*mech_name == '\0')
		return -1;
	return client_auth_begin(client, mech_name, init_resp);
}

int cmd_login(struct imap_client *client, const struct imap_arg *args)
{
	const char *user, *pass;
	string_t *plain_login, *base64;

	/* two arguments: username and password */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return -1;
	if (args[1].type != IMAP_ARG_ATOM && args[1].type != IMAP_ARG_STRING)
		return -1;
	if (args[2].type != IMAP_ARG_EOL)
		return -1;

	user = IMAP_ARG_STR(&args[0]);
	pass = IMAP_ARG_STR(&args[1]);

	if (!client->common.secured &&
	    client->common.set->disable_plaintext_auth) {
		if (client->common.set->verbose_auth) {
			client_syslog(&client->common, "Login failed: "
				      "Plaintext authentication disabled");
		}
		client->common.auth_tried_disabled_plaintext = TRUE;
		client->common.auth_attempts++;
		client_send_line(client,
			"* BAD [ALERT] Plaintext authentication not allowed "
			"without SSL/TLS, but your client did it anyway. "
			"If anyone was listening, the password was exposed.");
		client_send_tagline(client, "NO ["IMAP_RESP_CODE_CLIENTBUG"] "
				    AUTH_PLAINTEXT_DISABLED_MSG);
		return 1;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = buffer_create_dynamic(pool_datastack_create(), 64);
	buffer_append_c(plain_login, '\0');
	buffer_append(plain_login, user, strlen(user));
	buffer_append_c(plain_login, '\0');
	buffer_append(plain_login, pass, strlen(pass));

	base64 = buffer_create_dynamic(pool_datastack_create(),
        			MAX_BASE64_ENCODED_SIZE(plain_login->used));
	base64_encode(plain_login->data, plain_login->used, base64);
	return client_auth_begin(client, "PLAIN", str_c(base64));
}
