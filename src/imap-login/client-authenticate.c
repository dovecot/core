/* Copyright (C) 2002-2004 Timo Sirainen */

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

const char *client_authenticate_get_capabilities(int secured)
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

static void client_auth_input(void *context)
{
	struct imap_client *client = context;
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
	struct imap_client *client = (struct imap_client *)_client;
	struct const_iovec iov[3];
	size_t data_len;
	ssize_t ret;

	switch (reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		client_send_tagline(client, "OK Logged in.");
		client_destroy(client, t_strconcat(
			"Login: ", client->common.virtual_user, NULL));
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
		if (data == NULL)
			client_send_tagline(client, "Authentication failed");
		else {
			client_send_tagline(client, t_strconcat(
				"NO Authentication failed: ", data, NULL));
		}

		/* get back to normal client input. */
		if (client->io != NULL)
			io_remove(client->io);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		client_send_line(client, "* BYE Internal login failure. "
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

int cmd_authenticate(struct imap_client *client, struct imap_arg *args)
{
	const char *mech_name;

	/* we want only one argument: authentication mechanism name */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return -1;
	if (args[1].type != IMAP_ARG_EOL)
		return -1;

	mech_name = IMAP_ARG_STR(&args[0]);
	if (*mech_name == '\0')
		return FALSE;

	client_ref(client);
	sasl_server_auth_begin(&client->common, "IMAP", mech_name, NULL,
			       sasl_callback);
	if (!client->common.authenticating)
		return 1;

	/* following input data will go to authentication */
	if (client->io != NULL)
		io_remove(client->io);
	client->io = io_add(client->common.fd, IO_READ,
			    client_auth_input, client);
	return 0;
}

int cmd_login(struct imap_client *client, struct imap_arg *args)
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
		client_send_line(client,
			"* BAD [ALERT] Plaintext authentication is disabled, "
			"but your client sent password in plaintext anyway. "
			"If anyone was listening, the password was exposed.");
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
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

	client_ref(client);
	sasl_server_auth_begin(&client->common, "IMAP", "PLAIN",
			       str_c(base64), sasl_callback);
	if (!client->common.authenticating)
		return 1;

	/* don't read any input from client until login is finished */
	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	return 0;
}
