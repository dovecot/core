/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "auth-client.h"
#include "../pop3/capability.h"
#include "ssl-proxy.h"
#include "client.h"
#include "client-authenticate.h"
#include "pop3-proxy.h"

#include <stdlib.h>

#define POP3_SERVICE_NAME "pop3"

const char *capability_string = POP3_CAPABILITY_REPLY;

bool cmd_capa(struct pop3_client *client, const char *args ATTR_UNUSED)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	str_append(str, "+OK\r\n");
	str_append(str, capability_string);

	if (ssl_initialized && !client->common.tls)
		str_append(str, "STLS\r\n");
	if (!disable_plaintext_auth || client->common.secured)
		str_append(str, "USER\r\n");

	str_append(str, "SASL");
	mech = auth_client_get_available_mechs(auth_client, &count);
	for (i = 0; i < count; i++) {
		/* a) transport is secured
		   b) auth mechanism isn't plaintext
		   c) we allow insecure authentication
		*/
		if ((mech[i].flags & MECH_SEC_PRIVATE) == 0 &&
		    (client->common.secured || !disable_plaintext_auth ||
		     (mech[i].flags & MECH_SEC_PLAINTEXT) == 0)) {
			str_append_c(str, ' ');
			str_append(str, mech[i].name);
		}
	}
	str_append(str, "\r\n.");

	client_send_line(client, str_c(str));
	return TRUE;
}

static void client_auth_input(struct pop3_client *client)
{
	char *line;

	if (!client_read(client))
		return;

	/* @UNSAFE */
	line = i_stream_next_line(client->common.input);
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

static bool client_handle_args(struct pop3_client *client,
			       const char *const *args, bool success)
{
	const char *reason = NULL, *host = NULL, *destuser = NULL, *pass = NULL;
	string_t *reply;
	unsigned int port = 110;
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
		else if (strncmp(*args, "user=", 5) == 0) {
			/* already handled in login-common */
		} else if (auth_debug) {
			i_info("Ignoring unknown passdb extra field: %s",
			       *args);
		}
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
		if (pop3_proxy_new(client, host, port, destuser, pass) < 0)
			client_destroy_internal_failure(client);
		return TRUE;
	}

	if (!nologin)
		return FALSE;

	reply = t_str_new(128);
	str_append(reply, "-ERR ");
	if (reason != NULL)
		str_append(reply, reason);
	else if (temp)
		str_append(reply, AUTH_TEMP_FAILED_MSG);
	else
		str_append(reply, AUTH_FAILED_MSG);

	client_send_line(client, str_c(reply));

	if (!client->destroyed) {
		/* get back to normal client input. */
		if (client->io != NULL)
			io_remove(&client->io);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);
		client_input(client);
	}
	return TRUE;
}

static void sasl_callback(struct client *_client, enum sasl_server_reply reply,
			  const char *data, const char *const *args)
{
	struct pop3_client *client = (struct pop3_client *)_client;
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

		client_destroy_success(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_CLIENT_ERROR:
		if (args != NULL) {
			if (client_handle_args(client, args, FALSE))
				break;
		}

		msg = t_strconcat("-ERR ", data != NULL ?
				  data : AUTH_FAILED_MSG, NULL);
		client_send_line(client, msg);

		if (!client->destroyed && !client->auth_initializing) {
			/* get back to normal client input. */
			if (client->io != NULL)
				io_remove(&client->io);
			client->io = io_add(client->common.fd, IO_READ,
					    client_input, client);
			client_input(client);
		}
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		if (data == NULL)
			client_destroy_internal_failure(client);
		else {
			client_send_line(client,
				t_strconcat("-ERR [IN-USE] ", data, NULL));
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

		i_assert(client->io == NULL);
		client->io = io_add(client->common.fd, IO_READ,
				    client_auth_input, client);
		client_auth_input(client);
		return;
	}

	client_unref(client);
}

bool cmd_auth(struct pop3_client *client, const char *args)
{
	const struct auth_mech_desc *mech;
	const char *mech_name, *p;

	if (*args == '\0') {
		/* Old-style SASL discovery, used by MS Outlook */
		unsigned int i, count;

		client_send_line(client, "+OK");
		mech = auth_client_get_available_mechs(auth_client, &count);
		for (i = 0; i < count; i++) {
			if ((mech[i].flags & MECH_SEC_PRIVATE) == 0 &&
			    (client->common.secured || disable_plaintext_auth ||
			     (mech[i].flags & MECH_SEC_PLAINTEXT) == 0))
		 		client_send_line(client, mech[i].name);
		}
 		client_send_line(client, ".");
 		return TRUE;
	}

	/* <mechanism name> <initial response> */
	p = strchr(args, ' ');
	if (p == NULL) {
		mech_name = args;
		args = "";
	} else {
		mech_name = t_strdup_until(args, p);
		args = p+1;
	}

	client_ref(client);
	sasl_server_auth_begin(&client->common, POP3_SERVICE_NAME, mech_name,
			       args, sasl_callback);
	if (!client->common.authenticating)
		return TRUE;

	/* don't handle input until we get the initial auth reply */
	if (client->io != NULL)
		io_remove(&client->io);
	return TRUE;
}

static bool check_plaintext_auth(struct pop3_client *client)
{
	if (client->common.secured || !disable_plaintext_auth)
		return TRUE;

	if (verbose_auth) {
		client_syslog(&client->common, "Login failed: "
			      "Plaintext authentication disabled");
	}
	client_send_line(client, "-ERR "AUTH_PLAINTEXT_DISABLED_MSG);
	client->common.auth_tried_disabled_plaintext = TRUE;
	client->common.auth_attempts++;
	return FALSE;
}

bool cmd_user(struct pop3_client *client, const char *args)
{
	if (!check_plaintext_auth(client))
		return TRUE;

	i_free(client->last_user);
	client->last_user = i_strdup(args);

	client_send_line(client, "+OK");
	return TRUE;
}

bool cmd_pass(struct pop3_client *client, const char *args)
{
	string_t *plain_login, *base64;

	if (client->last_user == NULL) {
		/* client may ignore the USER reply and only display the error
		   message from PASS */
		if (!check_plaintext_auth(client))
			return TRUE;

		client_send_line(client, "-ERR No username given.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = t_str_new(128);
	str_append_c(plain_login, '\0');
	str_append(plain_login, client->last_user);
	str_append_c(plain_login, '\0');
	str_append(plain_login, args);

	i_free(client->last_user);
	client->last_user = NULL;

	base64 = buffer_create_dynamic(pool_datastack_create(),
        			MAX_BASE64_ENCODED_SIZE(plain_login->used));
	base64_encode(plain_login->data, plain_login->used, base64);

	client_ref(client);
	client->auth_initializing = TRUE;
	sasl_server_auth_begin(&client->common, POP3_SERVICE_NAME, "PLAIN",
			       str_c(base64), sasl_callback);
	client->auth_initializing = FALSE;
	if (!client->common.authenticating)
		return TRUE;

	/* don't read any input from client until login is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return TRUE;
}

bool cmd_apop(struct pop3_client *client, const char *args)
{
	buffer_t *apop_data, *base64;
	const char *p;

	if (client->apop_challenge == NULL) {
		if (verbose_auth) {
			client_syslog(&client->common,
				      "APOP failed: APOP not enabled");
		}
	        client_send_line(client, "-ERR APOP not enabled.");
		return TRUE;
	}

	/* <username> <md5 sum in hex> */
	p = strchr(args, ' ');
	if (p == NULL || strlen(p+1) != 32) {
		if (verbose_auth) {
			client_syslog(&client->common,
				      "APOP failed: Invalid parameters");
		}
	        client_send_line(client, "-ERR Invalid parameters.");
		return TRUE;
	}

	/* APOP challenge \0 username \0 APOP response */
	apop_data = buffer_create_dynamic(pool_datastack_create(), 128);
	buffer_append(apop_data, client->apop_challenge,
		      strlen(client->apop_challenge)+1);
	buffer_append(apop_data, args, (size_t)(p-args));
	buffer_append_c(apop_data, '\0');

	if (hex_to_binary(p+1, apop_data) < 0) {
		if (verbose_auth) {
			client_syslog(&client->common, "APOP failed: "
				      "Invalid characters in MD5 response");
		}
		client_send_line(client,
				 "-ERR Invalid characters in MD5 response.");
		return TRUE;
	}

	base64 = buffer_create_dynamic(pool_datastack_create(),
        			MAX_BASE64_ENCODED_SIZE(apop_data->used));
	base64_encode(apop_data->data, apop_data->used, base64);

	client_ref(client);
	sasl_server_auth_begin(&client->common, POP3_SERVICE_NAME, "APOP",
			       str_c(base64), sasl_callback);
	if (!client->common.authenticating)
		return TRUE;

	/* don't read any input from client until login is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return TRUE;
}
