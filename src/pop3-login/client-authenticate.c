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
		        - but don't advertise AUTH=PLAIN, as RFC 2595 requires
		*/
		if (mech[i].advertise &&
		    (client->secured || !mech[i].plaintext)) {
			str_append_c(str, ' ');
			str_append(str, mech[i].name);
		}
	}

	client_send_line(client, t_strconcat("+OK\r\n" POP3_CAPABILITY_REPLY,
					     (ssl_initialized && !client->tls) ?
					     "STLS\r\n" : "",
					     str_c(str),
					     "\r\n.", NULL));
	return TRUE;
}

static void client_auth_input(void *context)
{
	struct pop3_client *client = context;
	buffer_t *buf;
	char *line;
	size_t linelen, bufsize;

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

	linelen = strlen(line);
	buf = buffer_create_static_hard(pool_datastack_create(), linelen);

	if (base64_decode(line, linelen, NULL, buf) < 0) {
		/* failed */
		sasl_server_auth_cancel(&client->common, "Invalid base64 data");
	} else if (client->common.auth_request == NULL) {
		sasl_server_auth_cancel(&client->common,
					"Don't send unrequested data");
	} else {
		auth_client_request_continue(client->common.auth_request,
					     buf->data, buf->used);
	}

	/* clear sensitive data */
	safe_memset(line, 0, linelen);

	bufsize = buffer_get_used_size(buf);
	safe_memset(buffer_free_without_data(buf), 0, bufsize);
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
		io_remove(client->io);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
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
	string_t *buf;
	size_t argslen;

	if (*args == '\0') {
		/* Old-style SASL discovery, used by MS Outlook */
		int i, count;
		client_send_line(client, "+OK");
		mech = auth_client_get_available_mechs(auth_client, &count);
		for (i = 0; i < count; i++) {
			if (mech[i].advertise) {
		 		client_send_line(client, mech[i].name);
			}
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

	argslen = strlen(args);
	buf = buffer_create_static_hard(pool_datastack_create(), argslen);

	if (base64_decode(args, argslen, NULL, buf) < 0) {
		/* failed */
		client_send_line(client, "-ERR Invalid base64 data.");
		return TRUE;
	}

	client_ref(client);
	sasl_server_auth_begin(&client->common, "POP3", mech_name,
			       buf->data, buf->used, sasl_callback);
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
	if (!client->secured && disable_plaintext_auth) {
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
	string_t *plain_login;

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

	client_ref(client);
	sasl_server_auth_begin(&client->common, "POP3", "PLAIN",
			       plain_login->data, plain_login->used,
			       sasl_callback);
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
	buffer_t *apop_data;
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

	client_ref(client);
	sasl_server_auth_begin(&client->common, "POP3", "APOP",
			       apop_data->data, apop_data->used, sasl_callback);
	if (!client->common.authenticating)
		return TRUE;

	/* don't read any input from client until login is finished */
	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}
	return TRUE;
}
