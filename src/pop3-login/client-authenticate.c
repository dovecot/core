/* Copyright (C) 2002-2004 Timo Sirainen */

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

int cmd_capa(struct pop3_client *client, const char *args __attr_unused__)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	str_append(str, "SASL");

	mech = auth_client_get_available_mechs(auth_client, &count);
	for (i = 0; i < count; i++) {
		/* a) transport is secured
		   b) auth mechanism isn't plaintext
		   c) we allow insecure authentication
		*/
		if ((mech[i].flags & MECH_SEC_PRIVATE) == 0 &&
		    (client->common.secured || disable_plaintext_auth ||
		     (mech[i].flags & MECH_SEC_PLAINTEXT) == 0)) {
			str_append_c(str, ' ');
			str_append(str, mech[i].name);
		}
	}

	client_send_line(client,
			 t_strconcat("+OK\r\n" POP3_CAPABILITY_REPLY,
				     (ssl_initialized && !client->common.tls) ?
				     "STLS\r\n" : "",
				     str_c(str), "\r\n.", NULL));
	return TRUE;
}

static void client_auth_input(void *context)
{
	struct pop3_client *client = context;
	char *line;

	if (!client_read(client))
		return;

	/* @UNSAFE */
	line = i_stream_next_line(client->input);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0) {
		sasl_server_auth_cancel(&client->common,
					"Authentication aborted");
		return;
	}

	if (client->common.auth_request == NULL) {
		sasl_server_auth_cancel(&client->common,
					"Don't send unrequested data");
	} else {
		auth_client_request_continue(client->common.auth_request, line);
	}

	/* clear sensitive data */
	safe_memset(line, 0, strlen(line));
}

static void sasl_callback(struct client *_client, enum sasl_server_reply reply,
			  const char *data)
{
	struct pop3_client *client = (struct pop3_client *)_client;
	struct const_iovec iov[3];
	size_t data_len;
	ssize_t ret;

	switch (reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		client_send_line(client, "+OK Logged in.");
		client_destroy(client, t_strconcat(
			"Login: ", client->common.virtual_user, NULL));
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
		if (data == NULL)
			client_send_line(client, "-ERR Authentication failed");
		else {
			client_send_line(client, t_strconcat(
				"-ERR Authentication failed: ", data, NULL));
		}

		/* get back to normal client input. */
		if (client->io != NULL)
			io_remove(client->io);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		client_send_line(client,
				 "-ERR [IN-USE] Internal login failure. "
				 "Refer to server log for more information.");
		client_destroy(client, t_strconcat("Internal login failure: ",
						   client->common.virtual_user,
						   NULL));
		break;
	case SASL_SERVER_REPLY_CONTINUE:
		data_len = strlen(data);
		iov[0].iov_base = "+ ";
		iov[0].iov_len = 2;
		iov[1].iov_base = data;
		iov[1].iov_len = data_len;
		iov[2].iov_base = "\r\n";
		iov[2].iov_len = 2;

		ret = o_stream_sendv(client->output, iov, 3);
		if (ret < 0)
			client_destroy(client, "Disconnected");
		else if ((size_t)ret != 2 + data_len + 2)
			client_destroy(client, "Transmit buffer full");
		else {
			/* continue */
			return;
		}
		break;
	}

	client_unref(client);
}

int cmd_auth(struct pop3_client *client, const char *args)
{
	const struct auth_mech_desc *mech;
	const char *mech_name, *p;

	if (*args == '\0') {
		/* Old-style SASL discovery, used by MS Outlook */
		int i, count;
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
	sasl_server_auth_begin(&client->common, "POP3", mech_name,
			       args, sasl_callback);
	if (!client->common.authenticating)
		return TRUE;

	/* following input data will go to authentication */
	if (client->io != NULL)
		io_remove(client->io);
	client->io = io_add(client->common.fd, IO_READ,
			    client_auth_input, client);
	return TRUE;
}

int cmd_user(struct pop3_client *client, const char *args)
{
	if (!client->common.secured && disable_plaintext_auth) {
		if (verbose_auth) {
			client_syslog(&client->common, "Login failed: "
				      "Plaintext authentication disabled");
		}
		client_send_line(client,
				 "-ERR Plaintext authentication disabled.");
		return TRUE;
	}

	i_free(client->last_user);
	client->last_user = i_strdup(args);

	client_send_line(client, "+OK");
	return TRUE;
}

int cmd_pass(struct pop3_client *client, const char *args)
{
	string_t *plain_login, *base64;

	if (client->last_user == NULL) {
		client_send_line(client, "-ERR No username given.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = t_str_new(128);
	str_append_c(plain_login, '\0');
	str_append(plain_login, client->last_user);
	str_append_c(plain_login, '\0');
	str_append(plain_login, args);

	base64 = buffer_create_dynamic(pool_datastack_create(),
        			MAX_BASE64_ENCODED_SIZE(plain_login->used));
	base64_encode(plain_login->data, plain_login->used, base64);

	client_ref(client);
	sasl_server_auth_begin(&client->common, "POP3", "PLAIN",
			       str_c(base64), sasl_callback);
	if (!client->common.authenticating)
		return TRUE;

	/* don't read any input from client until login is finished */
	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}
	return TRUE;
}

int cmd_apop(struct pop3_client *client, const char *args)
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
	sasl_server_auth_begin(&client->common, "POP3", "APOP",
			       str_c(base64), sasl_callback);
	if (!client->common.authenticating)
		return TRUE;

	/* don't read any input from client until login is finished */
	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}
	return TRUE;
}
