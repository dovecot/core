/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-parser.h"
#include "auth-client.h"
#include "client.h"
#include "client-authenticate.h"
#include "imap-proxy.h"

#include <stdlib.h>

#define IMAP_SERVICE_NAME "imap"

static void client_auth_failed(struct imap_client *client);

const char *client_authenticate_get_capabilities(bool secured)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	mech = auth_client_get_available_mechs(auth_client, &count);
	for (i = 0; i < count; i++) {
		/* a) transport is secured
		   b) auth mechanism isn't plaintext
		   c) we allow insecure authentication
		*/
		if ((mech[i].flags & MECH_SEC_PRIVATE) == 0 &&
		    (secured || !disable_plaintext_auth ||
		     (mech[i].flags & MECH_SEC_PLAINTEXT) == 0)) {
			str_append_c(str, ' ');
			str_append(str, "AUTH=");
			str_append(str, mech[i].name);
		}
	}

	return str_c(str);
}

static void client_auth_input(struct imap_client *client)
{
	char *line;

	if (!client_read(client))
		return;

	if (client->skip_line) {
		if (i_stream_next_line(client->input) == NULL)
			return;

		client->skip_line = FALSE;
	}

	/* @UNSAFE */
	line = i_stream_next_line(client->input);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0) {
		sasl_server_auth_client_error(&client->common,
					      "Authentication aborted");
	} else {
		auth_client_request_continue(client->common.auth_request, line);
		io_remove(&client->io);

		/* clear sensitive data */
		safe_memset(line, 0, strlen(line));
	}
}

static bool client_handle_args(struct imap_client *client,
			       const char *const *args, bool success)
{
	const char *reason = NULL, *host = NULL, *destuser = NULL, *pass = NULL;
	string_t *reply;
	unsigned int port = 143;
	bool proxy = FALSE, temp = FALSE, nologin = !success;

	for (; *args != NULL; args++) {
		if (strcmp(*args, "nologin") == 0)
			nologin = TRUE;
		else if (strcmp(*args, "proxy") == 0)
			proxy = TRUE;
		else if (strcmp(*args, "temp") == 0)
			temp = TRUE;
		else if (strncmp(*args, "reason=", 7) == 0)
			reason = *args + 7;
		else if (strncmp(*args, "host=", 5) == 0)
			host = *args + 5;
		else if (strncmp(*args, "port=", 5) == 0)
			port = atoi(*args + 5);
		else if (strncmp(*args, "destuser=", 9) == 0)
			destuser = *args + 9;
		else if (strncmp(*args, "pass=", 5) == 0)
			pass = *args + 5;
	}

	if (destuser == NULL)
		destuser = client->common.virtual_user;

	if (proxy &&
	    !login_proxy_is_ourself(&client->common, host, port, destuser)) {
		/* we want to proxy the connection to another server.
		   don't do this unless authentication succeeded. with
		   master user proxying we can get FAIL with proxy still set.

		   proxy host=.. [port=..] [destuser=..] pass=.. */
		if (!success)
			return FALSE;
		if (imap_proxy_new(client, host, port, destuser, pass) < 0)
			client_destroy_internal_failure(client);
		return TRUE;
	}

	if (!proxy && host != NULL) {
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
			client_destroy(client, "Login with referral");
			return TRUE;
		}
	} else if (nologin) {
		/* Authentication went ok, but for some reason user isn't
		   allowed to log in. Shouldn't probably happen. */
		reply = t_str_new(128);
		if (reason != NULL)
			str_printfa(reply, "NO %s", reason);
		else if (temp)
			str_append(reply, "NO "AUTH_TEMP_FAILED_MSG);
		else
			str_append(reply, "NO "AUTH_FAILED_MSG);
		client_send_tagline(client, str_c(reply));
	} else {
		/* normal login/failure */
		return FALSE;
	}

	i_assert(nologin);

	if (!client->destroyed) {
		/* get back to normal client input. */
		if (client->io != NULL)
			io_remove(&client->io);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);
	}
	return TRUE;
}

static void sasl_callback(struct client *_client, enum sasl_server_reply reply,
			  const char *data, const char *const *args)
{
	struct imap_client *client = (struct imap_client *)_client;
	struct const_iovec iov[3];
	const char *msg;
	size_t data_len;

	i_assert(!client->destroyed ||
		 reply == SASL_SERVER_REPLY_CLIENT_ERROR ||
		 reply == SASL_SERVER_REPLY_MASTER_FAILED);

	switch (reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		if (args != NULL) {
			if (client_handle_args(client, args, TRUE))
				break;
		}

		client_send_tagline(client, "OK Logged in.");
		client_destroy(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_CLIENT_ERROR:
		if (args != NULL) {
			if (client_handle_args(client, args, FALSE))
				break;
		}

		msg = reply == SASL_SERVER_REPLY_AUTH_FAILED ? "NO " : "BAD ";
		msg = t_strconcat(msg, data != NULL ? data : AUTH_FAILED_MSG,
				  NULL);
		client_send_tagline(client, msg);

		if (!client->destroyed)
			client_auth_failed(client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		if (data == NULL)
			client_destroy_internal_failure(client);
		else {
			client_send_tagline(client,
					    t_strconcat("NO ", data, NULL));
			client_destroy(client, data);
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
	client_ref(client);
	sasl_server_auth_begin(&client->common, IMAP_SERVICE_NAME, mech_name,
			       init_resp, sasl_callback);
	if (!client->common.authenticating)
		return 1;

	/* don't handle input until we get the initial auth reply */
	if (client->io != NULL)
		io_remove(&client->io);
	client_set_auth_waiting(client);
	return 0;
}

static void client_auth_failed(struct imap_client *client)
{
	/* get back to normal client input. */
	if (client->io != NULL)
		io_remove(&client->io);
	client->io = io_add(client->common.fd, IO_READ,
			    client_input, client);

	timeout_remove(&client->to_auth_waiting);
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

	if (!client->common.secured && disable_plaintext_auth) {
		if (verbose_auth) {
			client_syslog(&client->common, "Login failed: "
				      "Plaintext authentication disabled");
		}
		client->common.auth_tried_disabled_plaintext = TRUE;
		client_send_line(client,
			"* BAD [ALERT] Plaintext authentication is disabled, "
			"but your client sent password in plaintext anyway. "
			"If anyone was listening, the password was exposed.");
		client_send_tagline(client, "NO "AUTH_PLAINTEXT_DISABLED_MSG);
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
